# Handoff for a new agent

Read this first; it costs less than re-deriving the state from the code. `CLAUDE.md` loads by itself and
has the architecture, file map and rules. Then read, only as far as you need:
`PLAN.md` ("Where it stands" and "Next steps"), `BENCHMARKS.md` ("What the numbers say" and the last rows
of each table), `CONTRIBUTING.md` ("Where to make which change").

## State (2026-10-28)

- Branch `claude/exciting-lovelace-89zljp`; everything is committed and pushed (last: `09c6820`). Work and
  push on that branch; no pull request unless asked.
- Tests: `python -m pytest tests`, 425 passed, 1 skipped (about 2 minutes). Keep them passing in any order.
- Benchmarks, latest valid runs, strict scoring: OU 86.7% (`20261022-080757`), DC 91.3% (`085413`),
  Injector 75.0% (`083942`), CorporateSecrets 82.1% (`20261021-081326`). Three earlier OU runs: 78.7-80.0%.
- Latest feature, not measured yet: `copilot/established.py` (`76a558d`). After each answer, code keeps
  its lines citing records the dossier doesn't, plus "searched, nothing found" lines; later conversations
  get them under the dossier. It works forward only: an earlier answer is not rewritten.

## How the user works

- Runs the benchmarks on their own machine (Windows: Velociraptor dead-disk client, Volatility, model
  `gpt-5.6-luna`) and uploads the scorecard `.md` (rarely the `.json`). This container has no Velociraptor,
  model or images: you never run benchmarks yourself.
- Writes short messages ("go", "do the first one"); expects you to act, then report briefly and plainly.
  Watches token use: don't re-read large files you don't need.
- Wants honest numbers. When a score was helped by the scorer, say so and fix the scorer, even if the
  number goes down.

## When a scorecard arrives

1. Read the header: code commit (`+ local changes` is normal), data source (`--from-case`), the
   "Knowledge / limits / triage" line, **Setup** warnings, "Where the time went", invalid IDs, forbidden
   claims. A run with Velociraptor down or triage unfinished is not comparable: mark it invalid.
2. Read the per-question table, then every ✗ and every "time ✗" with its answer text. For each miss decide:
   agent miss, scorer misfire (a denial misread, a time missed), or a key problem.
3. Re-score with the current scorer. The JSON is usually missing, so score the answers inside the `.md`:
   ```python
   import re, sys; sys.path.insert(0, ".")
   from copilot import benchmark as b
   md = open(PATH, encoding="utf-8").read()
   spec = b.load_spec("cases/<name>/benchmark.yaml")
   answers = dict(re.findall(r"^## (\w+): .*?<summary>Answer</summary>\n(.*?)</details>", md, re.S | re.M))
   # for each question q and fact f (skip scored: false): b.score_fact(answers[q["id"]], f, spec)
   ```
4. Before you change the scorer or a key, keep a copy of `copilot/benchmark.py`, then compare the old and
   new results on every saved scorecard. Commit only if each change is one you would defend; record
   re-scores as "new% (old% as run)".
5. Add a row to `BENCHMARKS.md` (what changed, what was found or missed and why, tokens, minutes), and
   update `PLAN.md` where the numbers or weaknesses changed.
6. Fix generic causes, not this image's facts: prefer code (a lead in `leads.py`, a check in `checks.py`, a
   setup check in `benchmark.py`) over prompt wording. Prompt-only fixes have not held across runs.

## Lessons that cost runs (don't repeat them)

- Prompts, tool descriptions and `knowledge_data/` must stay generic: no file names, IPs or users from
  the test cases. Tests may use such values.
- A lead that lists items oldest first and keeps 15 can hide the one that matters behind a tool suite of
  70 files. Group items, or rank by what matters.
- A whole-second NTFS creation time was probably copied from an archive or set by hand: it is not when
  the file arrived (`leads.COPIED_TIME`). The $SI change time, MFT $FN times or the USN journal are.
- `--from-case` copies the source run's triage only. A triage entry whose parameters changed since is
  collected again (`collection.covers`). The benchmark stops when Velociraptor doesn't answer.
- Scorer: a fact named only to deny or doubt it doesn't count (`denied`); a list's lead-in denies its
  items only when the denial is about the list itself; a time can end a label ("**23:28:30:**"). A time
  near the fact's words can belong to the next line: tighten that fact's `tolerance_seconds`.
- Tests script the model's responses in order (`ScriptedLLM`, `FakeVQL` in `tests/conftest.py`): an
  extra model call per turn would consume the next scripted answer and break many tests. That is why
  `established.py` uses no model.
- Verify a new feature on real answers before committing: the uploaded scorecards contain them.

## Next steps (from PLAN.md, the user decides)

1. One DC run on `09c6820` (`--from-case bench-szechuan-dc-20261022-085413`, about 7 minutes) checks
   `established.py`: do later answers cite earlier statements, and does the score stay in 83-96%?
2. Team readiness: an investigator reviews findings before they reach the report; PDF export and report
   sharing; audit, evidence manifest, tested export/restore; deployment and backup guidance.
3. Speed: agent collections are most of the wait (OU: 19 of 26 minutes). Parallel triage, not blocking
   on a slow collection.
4. A shorter system prompt now that the leads carry more of the work; check with the benchmarks.
5. Open in the OU key: the timeline says `admin` had RDP from 31.220.85.162 at 19:53:11; the key has a
   network logon at 19:53:08 and the RDP at 20:11:00. Check it in the records before changing the key.
6. No benchmark is blind any more: an unbiased number needs a new image.

## Commits

- End commit messages with the attribution trailers the session's system reminder gives (Co-Authored-By
  and Claude-Session lines). No model names anywhere in the repository.
- Never commit secrets or evidence (`api_client.yaml`, `server.yaml`, `auth.yaml`, `cases/*/data/`,
  `benchmark_results/`, `feedback_exports/`...): they are git-ignored; keep it that way.
