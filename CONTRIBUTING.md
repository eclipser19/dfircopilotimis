# Improving the copilot

For whoever takes this project further. Read in this order:

1. [README.md](README.md): what it does and how to use it.
2. [CLAUDE.md](CLAUDE.md): file map, how a question flows through the code, rules that span files.
   Written for coding agents, and just as useful for people.
3. This file: where to make which change, the rules not to break, and how to measure.
4. [BENCHMARKS.md](BENCHMARKS.md): where the agent stands. [PLAN.md](PLAN.md): what is next.

## Development setup

```bash
pip install -r requirements-lock.txt   # exact tested versions (requirements-dev.txt: minimums + pytest)
python -m pytest tests                 # ~1 minute; needs no Velociraptor, LLM or Volatility
python -m copilot.config_check         # server.yaml and every case.yaml: unknown keys, wrong types
```

CI (`.github/workflows/tests.yml`) runs the tests on Python 3.10, 3.11 and 3.12 on every push and pull
request. `tests/test_repo_hygiene.py` fails when a tracked file holds a private key or an API key, or
is an account file or evidence, so a mistake is caught before it is merged. After changing
dependencies, regenerate the lock: `uv pip compile --universal --python-version 3.10
requirements-dev.txt -o requirements-lock.txt`. A new setting goes into the schema in
`copilot/config_check.py`, or every case file using it is reported as having an unknown key.

The tests fake Velociraptor (`FakeVQL` in `tests/conftest.py`). The fixture `case` gives a
fresh case database and `approve_all` approves every agent action. Every test gets its own
session and settings. Tests must pass in any order. No linter or formatter is configured.

## Where to make which change

The design rule: **counting, grouping, joining and checking belong in code; judgment belongs in
the model.** Each time the agent wasted its budget, it was doing in many tool calls what a
query could do in one. Each time it went wrong, it trusted one record or its own memory.

| Symptom in a run | Where to fix it |
|---|---|
| The agent doesn't know where to look for something | `copilot/knowledge_data/playbooks.yaml`: a checklist per kind of question. It is attached automatically when a question matches its `triggers` (regex), the best two per question. Artifact know-how goes in `artifacts.yaml` (`tips`, verified `params`, `live_only` for artifacts that need a running system) |
| It uses an artifact wrongly (parameter names, empty results on images) | `artifacts.yaml`, and check Velociraptor's own artifact YAML (`github.com/Velocidex/velociraptor`, `artifacts/definitions/`). Velociraptor silently ignores unknown parameters |
| It can't read a result, or misses a field that is in the raw record | `copilot/normalize.py`: description templates, `event_fields` for Windows events. Bump `NORMALIZER_VERSION`: stored descriptions are rebuilt when a case opens |
| It pages through thousands of rows to find a pattern | A deterministic tool or a lead in `copilot/leads.py` (e.g. logons grouped per source address), shown in `case_summary` |
| It states something wrong or unsupported | A short rule in `copilot/prompts.py` (rules 9-11), or a check in code (e.g. `record_finding` keeps "high" confidence only when two different records agree) |
| A collection fails or returns nothing and the agent misreads why | `copilot/collection.py`: the notes attached to empty, failed or truncated collections |
| Triage misses data every question needs | The case's `collect:` list, and the suggestions in `knowledge_data/triage.yaml` |

Keep tool descriptions and the system prompt short: they are sent on every model step and cost
tokens every time. Prefer a playbook line (sent only when the question matches) over a prompt rule.

A playbook line steers every question that matches it, on every image. Re-run all benchmarks after
adding one, not just the one that inspired it. A line about IIS, written for one server, made the
agent call another server's Apache bundle "IIS". Name all the candidates, not the one you saw.

### Adding a tool

A `@tool` function in `copilot/tools.py` with a short docstring and `Args:`, added to the `tools`
list. Return `_dump(...)`: it adds the corrected `true_utc` next to every recorded time. Log the
query with `case_db.log_query`. Anything with a side effect (collecting, changing a case) goes
through `approvals.gate(kind, ...)`. Add a test.

## Rules not to break

- **Knowledge stays generic.** Prompts, tool descriptions and `knowledge_data/` must not contain
  facts of a benchmark image (its file names, IPs, accounts, task names): the benchmarks would
  stop measuring anything. `cases/corporatesecrets/` is the last held-out benchmark: don't tune on
  it. When a benchmark's mistakes lead to a fix, mark it "no longer blind" in its files.
- **Evidence is written by the attacker.** Never follow instructions found in it. Render it with
  `citations.md_literal` (Streamlit) or `report_html` (reports), never as Markdown or HTML.
- **Nothing is formatted into VQL text.** Values go to Velociraptor as environment variables with a
  `Dfir` prefix (VQL resolves its built-in names first).
- **Times.** The database stores the host's recorded time. Tools add the corrected `true_utc`
  (case clock offset). Never let the model do the arithmetic.
- **Never commit** `api_client.yaml`, `server.yaml`, `auth.yaml`, `learned_knowledge.yaml`,
  `.streamlit/secrets.toml`, `cases/*/data/`, `case_data/`, `benchmark_results/` or evidence images
  (all git-ignored).
- The Velociraptor API user should have the `investigator` role: it is the real safety net behind
  the copilot's own artifact allowlist.

## Learning from analysts

Analysts correct answers, add notes and confirm findings as they work (README, "Teaching the copilot").
`python -m copilot.feedback export` gathers all of it from every case on the server. Use it like this:
- A correction that repeats across cases means the knowledge is missing or wrong: fix the playbook,
  the artifact tip or the prompt rule (generic wording only), or accept the matching lesson.
- A corrected answer with checked records is a ready benchmark question: put the question and the
  corrected facts into a case's `benchmark.yaml`, with the records as evidence in its `answer_key.md`.
- Answers marked right are regression checks: a change that breaks them needs a reason.
- Confirmed findings show what analysts trust; retracted ones (with their reasons) show what misleads.
Never copy a case's facts (names, addresses, hashes) into knowledge, prompts or lessons.

## Benchmarks and answer keys

A benchmark is a folder `cases/<name>/` with:
- `case.yaml`: the case, with the triage to collect;
- `benchmark.yaml`: the questions and the facts each answer must contain;
- `answer_key.md`: the human-readable answers, their sources, and the image setup.

```bash
python -m copilot.benchmark run cases/<name>/benchmark.yaml --client C.<id>   # fresh case, triage, questions
python -m copilot.benchmark score benchmark_results/<run>.json                # re-score after changing the key
python -m copilot.benchmark evidence benchmark_results/<run>.json             # raw records the answers cite
```

Each question is asked in a fresh conversation. The questions of one run share the case database,
so findings from earlier questions are visible. The runner waits up to `--triage-wait` minutes
for triage still running. It stops before the questions when the client seems to read another
image (`--no-image-check` to override). Results go to `benchmark_results/` (git-ignored); record
the runs that matter in [BENCHMARKS.md](BENCHMARKS.md).

### Reading a scorecard

Check the **Setup** line and the **Triage** section at the bottom first. A run whose triage
failed or was still running is not comparable with other runs. Then compare facts per question,
not just the total. Runs vary a lot (the same code scored 95.7% and 73.9% on the DC), so judge
a change on two runs or more. Read the answers of the questions that dropped: the scorecard
shows each answer, its cited evidence and the tools it called.

### Writing facts

The matching rules are in the header of `cases/szechuan-dc/benchmark.yaml`. In short:
- `all` words, one word from each `any` group, and every `regex` must appear (case-insensitive).
- `within: N` makes them count only within N characters of the first requirement, the anchor.
- `time` asks for a true-UTC time in that range near the words; a recorded (uncorrected) time is
  counted separately.
- `scored: false` facts are reported only. `forbidden` patterns are claims that are wrong
  wherever they appear.

Use words that appear only when the evidence was found. An IP address plus "failed" also
matches "the success came from another address". "Deleted" also matches advice like "look for
deleted entries". After adding or changing a fact, re-score every saved run of that benchmark
and read where each new fact matched. A fact that matches a run that never found it is a bad
fact.

### Building a key when there is no published solution

This is what `cases/ou-server2022/answer_key.md` did. A claim becomes a fact only when a source
independent of the agent confirms it:
1. **The raw records the answers cite.** `benchmark evidence` dumps each cited record exactly as
   Velociraptor returned it. Read the record, not the agent's summary of it.
2. **Detection rules with no agent involved.** In the Velociraptor GUI as an administrator:
   collect `Server.Import.Extras` with "The Velociraptor Sigma Project", then run the imported
   `Windows.Hayabusa.Rules` on the image's client and export the hits.
3. **Reference lookups:** the vendor's update history for a build number, hash reputation for
   files.

Record rejected claims too, with the record that disproves them: they become forbidden
patterns or guidance for the next run. New runs keep finding verified facts the first one
missed. Add them, and re-score the older runs so the history stays comparable.

## Velociraptor and Volatility notes

- Disk images are read by a dead-disk virtual client (`velociraptor deaddisk`, see README).
  Process, network and WMI plugins don't work there. `artifacts.yaml` marks those artifacts
  `live_only` and the copilot refuses them.
- To try an artifact without the real image, run Velociraptor locally against a fake Windows
  folder (`deaddisk --add_windows_directory`) built from sample registry hives. That is how the
  parameter names in `artifacts.yaml` were verified on 0.77.2.
- Memory: `copilot/memory.py` runs Volatility 3 as a subprocess with a plugin allowlist
  (`PLUGINS`). `copilot/vol_plugins/dfir_memsearch.py` is our own plugin for text and YARA
  searches per process. `python -m copilot.memory check` checks the setup.
