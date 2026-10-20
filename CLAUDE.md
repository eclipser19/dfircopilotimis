# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

DFIR Copilot: an LLM agent (LangChain, any OpenAI-compatible endpoint) investigates a forensic
disk image through Velociraptor (dead-disk virtual client, gRPC API) and a memory image through
Volatility 3. Everything collected goes into a per-case SQLite database; the agent queries it with
tools, records findings with evidence IDs, and writes a templated report. Two front ends: a
Streamlit web app for several signed-in investigators (`app.py`) and a CLI (`main.py`).
`README.md` is the user guide; `PLAN.md` tracks status and next steps; `BENCHMARKS.md` records every
benchmark run that matters (add a row after each); `CONTRIBUTING.md` says where to make which change.

## Commands

```bash
pip install -r requirements-lock.txt           # exact tested versions (requirements-dev.txt: minimums + pytest)
python -m pytest tests                         # whole suite; needs no Velociraptor, LLM or Volatility
python -m pytest tests/test_memory.py          # one file
python -m pytest tests/test_app.py -k approve  # tests matching a name
streamlit run app.py                           # web app
python main.py                                 # CLI
python -m copilot.selftest [--flow F.XXXX]     # check the Velociraptor setup without the LLM
python -m copilot.config_check [file]          # unknown keys / wrong types in server.yaml and case files
python -m copilot.memory check [image]         # check Volatility, symbols, YARA, memory images
python -m copilot.auth add <user> [--admin]    # accounts (also: admin on|off, remove, list)
python -m copilot.lessons list|accept|remove   # lessons learned
python -m copilot.benchmark run cases/szechuan-dc/benchmark.yaml --client C.<id>   # score the agent (--no-investigate: without the dossier)
python -m copilot.benchmark score benchmark_results/<run>.json                     # re-score saved answers
```

No linter or formatter is configured. Tests pass in any order (they must keep doing so). CI runs them on
Python 3.10-3.12 (`.github/workflows/tests.yml`). New settings keys go into `copilot/config_check.py`'s schemas.

## How a question flows through the code

0. After the triage, `dossier.investigate()` runs one longer turn whose answer becomes the case
   dossier; `prompts.build_system_prompt()` appends the latest dossier to every conversation.
1. `app.py` / `main.py` take the investigator's text. `knowledge.with_playbooks()` appends the
   matching playbooks (regex `triggers` in `playbooks.yaml`) before it reaches the model.
2. `agent.run_turn()` loops: model call -> tool calls (`tools.py`) -> `ToolMessage`s, within
   `agent.max_steps` and `max_tokens_per_turn`. `trim_chat_history` blanks tool results older than
   the last 3 model steps; `repair_history` fixes histories left with unanswered tool calls.
3. Tools read the case database (`database.py`) or start work: `collection.collect()` (Velociraptor),
   `memory.run()` (Volatility). Anything with a side effect goes through `approvals.gate(kind, ...)`.
4. Collected rows pass through `normalize.py` (timestamps found by value, entities, event type,
   one-line description) into `records` + `timeline` + an FTS5 trigram index.
5. The answer is rendered with `citations.answer_markdown()`; cited evidence/finding IDs are
   looked up for the "Cited in this answer" panel (no LLM).

## File map

| File | What it does |
|---|---|
| `app.py` | Streamlit UI: sign-in, sidebar (case settings, triage picker, approvals, knowledge/lessons, database, findings, files), chat. Every agent turn ends with `st.rerun()` so the sidebar shows new approvals. |
| `main.py` | CLI entry; the loop itself is `agent.run_agent_loop`. |
| `copilot/agent.py` | Turn loop, token accounting (`TokenUsage`), history trimming/repair, CLI loop. |
| `copilot/dossier.py` | Investigate once, then answer: one longer turn in its own conversation writes the case dossier (timeline, findings, entities, hypotheses, contradictions, gaps), stored in the `dossiers` table; `prompt_section()` puts the latest into every system prompt. Run after triage (app, CLI), by `/investigate` / the sidebar button, and before benchmark questions. |
| `copilot/tools.py` | Every LangChain tool the model can call, and their descriptions (sent on every step: keep them short). `_dump` serialises results and adds `true_utc` fields. `record_finding` keeps "high" confidence only when two different records agree (prompt rule 11: correlate before claiming). |
| `copilot/prompts.py` | System prompt (rules, memory, lessons, approvals); the case part comes from `case_config.build_system_context()`. |
| `copilot/case_config.py` | `CaseConfig`: one case's `case.yaml` (scope, clock offset, IOCs, triage list, allow/denylists, limits, memory image). `case_config` is a proxy to the current session's case. |
| `copilot/cases.py` | Case folders `cases/<id>/case.yaml`: list, create, update (rewrites the YAML), switch, access control (owner/members/admin), sharing (`access.shared_with` / `share_findings`: others may start a case from its data, `can_reuse`, `copy_data(findings=)`), evidence sources (who may name a client/memory image, lock once data came from it, `evidence:` section). |
| `copilot/session.py` | One `Session` (active case + its DB connection + user) per browser session or CLI process. `PROVIDER` lets the app supply its own. |
| `copilot/database.py` | SQLite per case: records, timeline, FTS, collections, findings, audit log, outputs, conversation. `data_dir_for()` decides where. |
| `copilot/normalize.py` | Raw row -> record: timestamps, entities, event types, description templates. Windows event rows lead with `event_fields` (LogonType, user, ip, workstation, logon_id, by...; from EventData or the message text). Bump `NORMALIZER_VERSION` when templates/entities change (stored descriptions are rebuilt). |
| `copilot/collection.py` | Velociraptor collections: schedule, poll, ingest; time window into artifact date params; agent rules (parameter names must exist, heavy artifacts need a filter, csv params get their header); empty-result notes. |
| `copilot/vql_client.py` | gRPC client (pyvelociraptor), lazy, `api_client.yaml` / `DFIR_API_CONFIG`. |
| `copilot/memory.py` | Volatility 3 as a subprocess (`-r json`), plugin allowlist `PLUGINS`, triage, `strings` search done in Python, settings from `server.yaml` `memory:`. |
| `copilot/vol_plugins/dfir_memsearch.py` | Our own Volatility plugin (loaded with `-p`): text or YARA search per process. Runs inside Volatility, imports nothing from `copilot`. |
| `copilot/approvals.py` | Approval kinds (collect, memory, retract_finding, update/switch/create_case, lesson), modes confirm/auto/off per case, `ASK` hook set by the UI, `execute()` for queued requests. |
| `copilot/knowledge.py` + `knowledge_data/` | `artifacts.yaml` (first matching pattern wins; `live_only` = refused on images; verified `params`; tips), `playbooks.yaml`, `event_ids.yaml`, `triage.yaml` (suggestions). |
| `copilot/forensic_artifacts.py` | "Where is X stored?": search over `knowledge_data/forensic_artifacts.yaml` (generated from ForensicArtifacts, Apache-2.0; `python -m copilot.forensic_artifacts import <checkout>`), returning ready FileFinder / NTUser parameters; the `find_data_location` tool. |
| `copilot/lessons.py` | Lessons proposed by the agent, approved by a person, stored server-wide in `learned_knowledge.yaml`, merged into `knowledge.artifact_info`. Refuses case facts (IPs, hashes, domains). |
| `copilot/leads.py` | Leads computed without the LLM, shown in `case_summary`: logons per source address (`logon_sources`, also the `logon_summary` tool), account/group changes, services, tasks, log clearing/Defender, downloads by origin, programs in user folders. Parses the `event_fields` part of descriptions; cached per database state. |
| `copilot/citations.py` | Evidence/finding ID lookup for answers; `md_literal` / `answer_markdown` keep attacker text from rendering as Markdown, links, images or math. |
| `copilot/report.py`, `report_template.py`, `report_html.py`, `charts.py` | Report built from the DB (only the narrative comes from the LLM); HTML with `html=False` and a CSP; charts as static SVG. `report.Clock` converts recorded -> true UTC. |
| `copilot/outputs.py` | Files produced for download (reports, exports), registered per case. |
| `copilot/conversation.py` | Saves/restores each user's chat per case (`ui@user` / `agent@user`). |
| `copilot/settings.py`, `llm.py`, `auth.py` | `server.yaml` (env vars win), the chat model, local accounts (PBKDF2, lockout). |
| `copilot/iocs.py`, `commands.py`, `selftest.py` | IOC extraction, `/cases` `/case` `/help` chat commands, setup check. |
| `copilot/benchmark.py` | Benchmark runner: fresh `bench-*` case, triage (waits for unfinished flows: `finish_triage`), fixed questions in fresh conversations, scoring in code (facts, true-UTC times near the fact's words, uncorrected times, invalid IDs, forbidden claims), results in `benchmark_results/`. |
| `cases/szechuan/` | Example case (DFIR Madness "Szechuan Sauce" desktop) and `answer_key.md`; used to tune the knowledge. |
| `cases/szechuan-dc/` | The same case's domain controller: `case.yaml`, `benchmark.yaml` (questions and expected facts), `answer_key.md`. Benchmark (no longer fully blind). |
| `cases/corporatesecrets/` | CyberDefenders "CorporateSecrets" (insider case, AD1 logical image read as a folder): held-out benchmark; `answer_key.md` has the setup. |
| `cases/injector/` | CyberDefenders "Injector" (web server breach, raw disk + memory): benchmark (no longer fully blind); web logs via `Generic.Detection.Logs`. |
| `cases/ou-server2022/` | Open University "Compromised Windows Server 2022 (simulation)" (E01, RDP + ransomware): benchmark (no longer fully blind); no published solution, so its key was built from a blind run's cited records, Hayabusa hits and lookups (`answer_key.md`). |
| `tests/conftest.py` | `FakeVQL` (answers Velociraptor queries; `artifact_params` take names or dicts), fixtures `case`, `approve_all`, and isolation from real `server.yaml`/accounts/lessons. |

## Things that span several files

- **Sessions and proxies.** `case_config` and `case_db` are `CaseView` proxies onto
  `session.current()`: import them, never keep their attributes. Several Streamlit users share one
  process, so module-level state is shared; per-user state lives in the `Session` or `st.session_state`.
- **Approvals.** The CLI answers `ASK` immediately; Streamlit returns `"queued"`, the tool tells the
  model it is waiting, and `approvals.resolve()` runs it after the click, then the agent continues
  by itself. Investigator actions (sidebar buttons, commands) bypass approvals. A queued collect or
  memory request carries the client and memory image it was asked for (`bound`); `resolve()` refuses
  it if the case now points elsewhere.
- **Evidence sources.** Access is per source as well as per case: `cases.source_problem()` lets a user
  name a client or memory image only if no case uses it or they can open or reuse a case that does
  (shared with them: `cases.can_reuse`; admins: any; `login.new_evidence: admins` keeps unused ones for admins). `cases.collected_sources()` reads
  `collections.client_id` (`memory:<image>` for memory runs): a source with rows locks that setting,
  and `copy_data` compares it too. Provenance for the report: `evidence_files` (memory image SHA-256,
  hashed by `memory.image_identity` on the first run) and `case.yaml` `evidence:` for the disk image.
- **Times.** The database stores the *recorded* host time in fields named `timestamp_utc`,
  `first_seen`, `last_seen`. A case's `scope.clock_offset_minutes` gives the skew; tool results
  carry the corrected `true_utc` and answers must quote both. Never let the model do the arithmetic.
- **Attacker-controlled text.** Evidence can contain prompt injection and Markdown/HTML. Render it
  with `md_literal` (Streamlit) or `report_html` (reports); chat messages built by the app with
  `"literal": True` are already escaped.
- **VQL safety.** Every value goes to Velociraptor as an env variable with a `Dfir` prefix (VQL
  resolves built-in names first); nothing is formatted into query text. Velociraptor silently
  ignores undeclared artifact parameters, hence the parameter-name check for agent collections.
- **Dead-disk limits.** WMI, process and network plugins are disabled on images (`live_only` in
  `artifacts.yaml`). `lookupSID` is disabled too, but since Velociraptor 0.73 artifacts find user
  names in the registry instead, so browser history, UserAssist and PSReadline work (verified on
  0.77.2; the log line is treated as harmless). The `mft` accessor is not remapped, so
  `Windows.NTFS.ADSHunter` returns nothing (use `Windows.Analysis.EvidenceOfDownload`).
  `Generic.Client.Info` can't describe an image (WMI): machine registry values come from
  `Windows.Search.FileFinder` with `Accessor: registry`. Check Velociraptor's own artifact
  YAML (`github.com/Velocidex/velociraptor`, `artifacts/definitions/`) before assuming parameters.
- **Knowledge must stay generic.** The answer keys (`answer_key.md`, `benchmark.yaml`) score the
  agent, so prompts, tool descriptions and `knowledge_data/` must not contain facts of the test
  cases (their file names, IPs, users). Improve the agent on the desktop case, measure on the
  benchmarks; `cases/corporatesecrets/` is still held out, so don't tune on it.
- **Streamlit quirks.** `RerunException`/`StopException` are `BaseException` (they can cut a turn
  short: `repair_history`); widget state is dropped when a widget is not drawn, so selections are
  copied to plain keys in `on_change`; `AppTest` cannot keep `st.dialog` open, so editors live in
  the main area.
- **Never commit** `api_client.yaml`, `server.yaml`, `auth.yaml`, `learned_knowledge.yaml`,
  `.streamlit/secrets.toml`, `cases/*/data/` or `case_data/` (evidence). They are git-ignored.

## Configuration and data locations

- Cases: `DFIR_CASES_DIR` (default `cases/`); first case `DFIR_CASE_FILE` / `DFIR_CASE`.
- Case data (database, chats, outputs): `cases/<case-id>/data/`, next to its `case.yaml`
  (`database.data_dir_for`). `DFIR_DATA_DIR` puts it in `<DFIR_DATA_DIR>/<case-id>/` instead,
  `DFIR_CASE_DIR` in one folder. Old `case_data/<case-id>/` is still read until moved with
  `python -m copilot.cases move-data`.
- Server settings: `server.yaml` (`DFIR_SETTINGS`), copied from `server.example.yaml`: `llm`, `login`,
  `memory` (images_dir, symbols_dir, offline, timeout, yara_dir), `knowledge.learned_file`.
- Accounts: `auth.yaml` (`DFIR_AUTH_FILE`). Velociraptor API: `api_client.yaml` (`DFIR_API_CONFIG`).

## Glossary

- **Evidence ID**: 16-hex content hash of a collected record (re-collecting doesn't duplicate it).
- **Finding ID**: e.g. `60ad0e42-05d`; findings are the report's backbone and can be retracted.
- **Flow ID**: a Velociraptor collection (`F.XXXX`); memory runs use `MEM.<plugin>.<time>`.
- **Source**: the artifact a record came from; memory rows use `Memory.<volatility plugin>`.
- **Recorded vs true UTC**: host-clock time as stored vs corrected by the case clock offset.
- **Triage**: the case's `collect:` list (and memory `memory.collect`), run without the LLM.
- **Playbook**: a checklist for a kind of question; **lesson**: approved, server-wide knowledge.
- **Dossier**: the case summary an investigation turn writes; every later question starts from it.
- **Heavy artifact**: can return millions of rows; the agent must pass a filter or a <= 60 min window.
- **live_only**: an artifact that needs a running system; refused on disk images.
