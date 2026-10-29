# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

DFIR Copilot: an LLM agent (LangChain, any OpenAI-compatible endpoint) investigates a forensic
disk image through Velociraptor (dead-disk virtual client, gRPC API) and a memory image through
Volatility 3. Everything collected goes into a per-case SQLite database; the agent queries it with
tools, records findings with evidence IDs, and writes a templated report. Two front ends: a
Streamlit web app for several signed-in investigators (`app.py`) and a CLI (`main.py`).
`README.md` is the user guide; `PLAN.md` tracks status and next steps; `BENCHMARKS.md` records every
benchmark run that matters (add a row after each); `CONTRIBUTING.md` says where to make which change;
`HANDOFF.md` says where the work stands and how the user works (read it first in a new session);
`DEPLOY.md` is the install on a forensic machine: Windows (`install.ps1`) or Linux, SANS SIFT / Ubuntu
(`deploy/install.sh`, systemd); HTTPS, start at boot, backup.

## Commands

```bash
pip install -r requirements-lock.txt           # exact tested versions (requirements-dev.txt: minimums + pytest)
python -m pytest tests                         # whole suite; needs no Velociraptor, LLM or Volatility
python -m pytest tests/test_memory.py          # one file
python -m pytest tests/test_app.py -k approve  # tests matching a name
streamlit run app.py                           # web app
powershell -File install.ps1                   # fresh Windows machine: Python, packages, then copilot.install setup
sudo deploy/install.sh                         # SIFT / Ubuntu (code at /opt/dfir-copilot): account, .venv, service, setup
sudo dfir-admin <module> ...                   # on such a machine: a copilot command as the dfir account
python -m copilot.install add-image <E01|folder> --name N   # an image as its own dead-disk client
python -m copilot.install start                # Velociraptor + image clients + app (start.ps1, start.sh)
python -m copilot.install https --name N       # the app on the network over HTTPS (self-signed, or --cert/--key)
python main.py                                 # CLI
python -m copilot.selftest [--flow F.XXXX]     # check the Velociraptor setup without the LLM
python -m copilot.config_check [file]          # unknown keys / wrong types in server.yaml and case files
python -m copilot.memory check [image]         # check Volatility, symbols, YARA, memory images
python -m copilot.auth add <user> [--admin]    # accounts (also: admin on|off, remove, list)
python -m copilot.lessons list|accept|remove   # lessons learned
python -m copilot.feedback list|export         # what analysts noted, corrected and confirmed, all cases
python -m copilot.benchmark run cases/szechuan-dc/benchmark.yaml --client C.<id>   # score the agent (--no-investigate: without the dossier)
python -m copilot.benchmark score benchmark_results/<run>.json                     # re-score saved answers
```

No linter or formatter is configured. Tests pass in any order (they must keep doing so). CI runs them on
Python 3.10-3.12 (`.github/workflows/tests.yml`). New settings keys go into `copilot/config_check.py`'s schemas.

## How a question flows through the code

0. After the triage, `dossier.investigate()` runs one longer turn whose answer becomes the case
   dossier; `prompts.build_system_prompt()` appends the latest dossier to every conversation, and
   under it what later answers established (`established.py`).
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
| `app.py` | Streamlit UI: sign-in; sidebar (case picker, new case, approvals, knowledge/lessons); main area = case header + keyed tabs `TABS` (Chat, Findings & dossier, Evidence & data with search, Report & files, Case settings/access/sharing). Buttons that start work call `to_chat`; in the Chat tab, `start()` submits a job (`copilot/jobs.py`) and `follow()` shows its events until it ends, then `st.rerun()`s. Every run reloads the conversation from the case (`load_chat`), follows the user's running job if any, and offers **Continue** for one a stopped server interrupted. |
| `copilot/jobs.py` | Durable work for the web app: questions (`ask`), `investigate`, `triage`, `decide` (approvals) run in a thread pool of the server process on a `Session.fork()`; `jobs` / `job_events` tables hold state and progress, the conversation is checkpointed after every agent step. One active job per user and case. `recover()` marks another process's running jobs interrupted (their claimed approvals go back to pending, RUNNING memory flows to ERROR); `retry()` resumes a question from the saved history. Job bookkeeping uses its own connection to the starting case's DB (the agent may switch the job's session to another case). |
| `main.py` | CLI entry; the loop itself is `agent.run_agent_loop`. |
| `copilot/agent.py` | Turn loop, token accounting (`TokenUsage`), history trimming/repair, CLI loop. |
| `copilot/dossier.py` | Investigate once, then answer: one longer turn in its own conversation writes the case dossier (timeline, findings, entities, hypotheses, contradictions, gaps), stored in the `dossiers` table; `prompt_section()` puts the latest into every system prompt (`fit()` drops whole low-priority sections, never Gaps). Code, not the prompt, attaches the checklists the case needs (`checklists()`: web attack on `leads.web_server` signs, memory with an image) and appends a time check (`citations.time_mismatches`: times held neither as a timestamp nor in a field of the records cited on the same line). Run after triage (app, CLI), by `/investigate` / the Investigate button, and before benchmark questions. |
| `copilot/established.py` | What earlier answers established: after each answer (`jobs._turn`, the CLI, `benchmark.ask`) `record()` keeps, without the model, its lines citing records the dossier and earlier statements don't (an "Evidence:" line joins the statement above it) and its "searched, nothing found" lines; `prompt_section()` puts those made since the latest dossier under it in every system prompt (latest answers first when too long); listed in the Findings & dossier tab. Not findings: unreviewed, never in the report. |
| `copilot/feedback.py` | Investigators teach the copilot: notes and corrections per case (`feedback` table; `prompt_section()` puts them above the dossier in every system prompt), corrections of answers/dossiers (👎 in the app, `/wrong` in the CLI; `/note` `/notes` anywhere), confirmed findings (`findings.confirmed_by`, ✅ or `/confirm`, shown in `case_summary` and the report; the report says
DRAFT while some are unconfirmed, and `confirmed_findings_only` keeps those out), and `python -m copilot.feedback list|export` across all cases (to `feedback_exports/`, git-ignored). |
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
| `copilot/approvals.py` | Approval kinds (collect, memory, retract_finding, update/switch/create_case, lesson), modes confirm/auto/off per case, `ASK` hook set by the UI (the app: `queue`, requests in the `approval_requests` table per user; `pending`, `claim` once, `finish`), `execute()` for queued requests. |
| `copilot/knowledge.py` + `knowledge_data/` | `artifacts.yaml` (first matching pattern wins; `live_only` = refused on images; verified `params`; tips), `playbooks.yaml`, `event_ids.yaml`, `triage.yaml` (suggestions), `file_types.yaml`. |
| `copilot/forensic_artifacts.py` | "Where is X stored?": search over `knowledge_data/forensic_artifacts.yaml` (generated from ForensicArtifacts, Apache-2.0; `python -m copilot.forensic_artifacts import <checkout>`), returning ready FileFinder / NTUser parameters; the `find_data_location` tool. |
| `copilot/lessons.py` | Lessons proposed by the agent, approved by a person, stored server-wide in `learned_knowledge.yaml`, merged into `knowledge.artifact_info`. Refuses case facts (IPs, hashes, domains). |
| `copilot/leads.py` | Leads computed without the LLM, shown in `case_summary`: logons per source address (`logon_sources`, also the `logon_summary` tool), account/group changes, services, tasks, log clearing/Defender, downloads by origin, credentials used for other hosts (`explicit_credentials`: 4648 to another server, by program), shortcuts/jump lists/shellbags to other hosts (`remote_locations`: UNC, FTP/WebDAV, addresses, network folders), programs in user folders, files whose content is not their name (`renamed_content`), web searches and YouTube videos (`web_activity`, words decoded from search-page URLs), interactive sessions (`sessions`: logon to logoff by logon ID, two 4624s of one RDP logon merged; `by_logon_id` events are proof, `same_time_window` programs run (Prefetch/BAM/UserAssist run times only), persistence and files are time only; `sessions_to_check` compact, the `session_activity` tool in full), `autostart` entries pointing into user folders or through scripting tools, `timestamp_changes` (MFT SI_Lt_FN / USecZeros, USN BASIC_INFO_CHANGE without a data change, OS folders left out). Parses the `event_fields` part of descriptions; cached per database state. |
| `copilot/checks.py` | Collections the code makes before an investigation (`dossier.investigate` calls `before_investigation`): the MFT records of the files touched in the sessions to check (`touched_files`), FileRegex built RE2-safe, no time window, so `timestamp_changes` sees hand-set timestamps whatever the model would check. |
| `copilot/file_types.py` + `knowledge_data/file_types.yaml` | File types by their first bytes: one YARA rule `FileType_<type>` each; a parameter value `"@file_types"` is sent to Velociraptor as those rules (`collection.schedule`) but stored and audited by that name; `mismatch()` compares a typed file's extension with the type's usual ones. The triage runs it through `Generic.Detection.Yara.Glob` on the users' folders. |
| `copilot/citations.py` | Evidence/finding ID lookup for answers; `md_literal` / `answer_markdown` keep attacker text from rendering as Markdown, links, images or math. |
| `copilot/report.py`, `report_template.py`, `report_html.py`, `charts.py` | Report built from the DB (only the narrative comes from the LLM); HTML with `html=False` and a CSP; charts as static SVG. `report.Clock` converts recorded -> true UTC. |
| `copilot/outputs.py` | Files produced for download (reports, exports), registered per case. |
| `copilot/conversation.py` | Saves/restores each user's chat per case (`ui@user` / `agent@user` / `inbox@user`). Changes go through `append`, `update_message`, `save_history`, `begin` under a process lock (jobs and the page write the same conversation); `note_for_agent` leaves investigator actions in the inbox until the agent's next turn (`begin` moves them into the history). |
| `copilot/install.py`, `install.ps1`, `start.ps1`, `start.sh`, `deploy/` | Fresh-machine install, Windows or Linux (`SYSTEM`: the Velociraptor build, binary name, data folder `C:\dfir` or `/srv/dfir`; `deploy/install.sh` adds the dfir account, `/etc/dfir-copilot/env`, the systemd service running `start` (`start.sh --background`; plain `start.sh` runs `start` in the terminal), nightly `deploy/backup.sh`, `dfir-admin`): `setup` (Velociraptor downloaded and hash-checked, server config with every port on 127.0.0.1 and the datastore in the data folder, API config, `server.yaml` with the shared-server defaults and a `deploy:` section, self-signed or PKI certificate, first admin), `add-image` (own client config, writeback and remap per image; client ID read from the writeback), `start` (frontend, the images' clients, Streamlit on 0.0.0.0 only with TLS), `https` (a certificate into `server.yaml`). Data folder layout in `Layout`. |
| `copilot/settings.py`, `llm.py`, `auth.py` | `server.yaml` (env vars win), the chat model, local accounts (PBKDF2, lockout). |
| `copilot/iocs.py`, `commands.py`, `selftest.py` | IOC extraction, `/cases` `/case` `/help` chat commands, setup check. |
| `copilot/benchmark.py` | Benchmark runner: model checked first (`make_model` pings it), fresh `bench-*` case, triage (waits for unfinished flows: `finish_triage`) or `--from-case` (triage part only: `cases.copy_data(triage=)`, then the triage artifacts missing or collected with other parameters: `collection.covers`), investigation, fixed questions in fresh conversations, where the time went (model, collections, memory, tools: `TokenUsage.spent`) and what the run depended on (`run_settings`: knowledge hashes, lessons, normalizer, limits), scoring in code (facts, not counted where their clause denies or doubts them (`denied`); true-UTC times near the fact's words, uncorrected times, invalid IDs, forbidden claims, times not in cited records), commit recorded, results in `benchmark_results/`. |
| `cases/szechuan/` | Example case (DFIR Madness "Szechuan Sauce" desktop) and `answer_key.md`; used to tune the knowledge. |
| `cases/szechuan-dc/` | The same case's domain controller: `case.yaml`, `benchmark.yaml` (questions and expected facts), `answer_key.md`. Benchmark (no longer fully blind). |
| `cases/corporatesecrets/` | CyberDefenders "CorporateSecrets" (insider case, AD1 logical image read as a folder): benchmark run blind once (60.7%); its misses led to generic fixes, so no longer blind; `answer_key.md` has the setup. |
| `cases/injector/` | CyberDefenders "Injector" (web server breach, raw disk + memory): benchmark (no longer fully blind); web logs via `Generic.Detection.Logs`. |
| `cases/ou-server2022/` | Open University "Compromised Windows Server 2022 (simulation)" (E01, RDP + ransomware): benchmark (no longer fully blind); no published solution, so its key was built from a blind run's cited records, Hayabusa hits and lookups (`answer_key.md`). |
| `tests/conftest.py` | `FakeVQL` (answers Velociraptor queries; `artifact_params` take names or dicts), fixtures `case`, `approve_all`, and isolation from real `server.yaml`/accounts/lessons. |

## Things that span several files

- **Sessions and proxies.** `case_config` and `case_db` are `CaseView` proxies onto
  `session.current()`: import them, never keep their attributes. Several Streamlit users share one
  process, so module-level state is shared; per-user state lives in the `Session` or `st.session_state`.
- **Approvals.** The CLI answers `ASK` immediately; the app's `ASK` is `approvals.queue` (the request is
  stored in the case, the tool tells the model it is waiting), and a `decide` job claims it, runs
  `approvals.resolve()`, then the agent continues by itself. Investigator actions (sidebar buttons,
  commands) bypass approvals. A queued collect or memory request carries the client and memory image
  it was asked for (`bound`); `resolve()` refuses it if the case now points elsewhere.
- **Background jobs.** The app never runs agent turns, triage or approvals in the page's script run:
  `jobs.submit` runs them in a server thread on `session.Session.fork()` (same settings, own DB
  connection, set per thread with `session.use`). The page's `st.session_state.messages` /
  `chat_history` are a view reloaded every run; never write them, write through `conversation` or
  `tell_agent`. `collection.collect` reuses an identical running or usable flow (`same_collection`), so
  retries repeat no collection. Volatility output is streamed to a temp file and parsed with
  `memory.json_items`, capped at `max_rows`.
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
  benchmarks. No benchmark is blind any more (`cases/corporatesecrets/` was run blind once, at 60.7%): an
  unbiased number needs a new image.
- **Streamlit quirks.** `RerunException`/`StopException` are `BaseException` (they can cut a turn
  short: `repair_history`); widget state is dropped when a widget is not drawn, so selections are
  copied to plain keys in `on_change`; `AppTest` cannot keep `st.dialog` open, so editors live in
  the main area.
- **Never commit** `api_client.yaml`, `server.yaml`, `auth.yaml`, `learned_knowledge.yaml`,
  `.streamlit/secrets.toml`, `cases/*/data/`, `case_data/` (evidence) or `feedback_exports/` (answers quote
  evidence). They are git-ignored.

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
- **Established statements**: lines of answers citing records the dossier doesn't, kept by code; later
  questions start from them too (`established.py`).
- **Note**: a fact or correction an investigator gives; it outranks the dossier in that case's prompts.
- **Heavy artifact**: can return millions of rows; the agent must pass a filter or a <= 60 min window.
- **live_only**: an artifact that needs a running system; refused on disk images.
