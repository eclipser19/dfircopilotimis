# DFIR Copilot: Development Plan

LLM-driven DFIR copilot: Velociraptor collects from a mounted forensic image, results are
normalized into a local case database, the agent investigates through database tools and
records findings, and a templated DFIR report is generated from those findings.

Legend: [x] done and tested · [~] partially done · [ ] not started

---

## Step 1: Correctness & safety ✅
- [x] Lazy Velociraptor connection (importing the package no longer needs `api_client.yaml`); gRPC timeouts; results streamed.
- [x] All values (client ID, artifact, parameters, flow ID) passed as `VQLEnv` variables, never formatted into VQL.
- [x] Velociraptor errors from `response.log` surfaced to the agent.
- [x] Case pinned to one client (`velociraptor.client_id` in `case.yaml`); any other client is unreachable.
- [x] Artifact allowlist (glob patterns, overridable) + hard denylist for command-execution / server artifacts.
- [x] Raw server VQL off by default (`agent.allow_raw_vql`); when on, write/execute/network functions are refused. Replaced in normal use by `list_artifacts` / `describe_artifact`.
- [x] Collections tracked in a `collections` table: honest RUNNING / FINISHED / ERROR status, `check_collection` to finish later, each flow ingested once.
- [x] Hostname lookup fixed (`clients(client_id=...)`).
- [x] Deterministic evidence IDs (content hash): re-collecting no longer duplicates events.
- [x] `record_finding` rejects evidence IDs that don't exist.
- [x] Auto-collection runs in code, not by asking the LLM.
- [x] One system prompt and one LLM factory shared by CLI and Streamlit; API key no longer put in `os.environ`.
- [x] `case_data/` git-ignored; `requirements.txt`; pytest suite (`tests/`).

## Step 2: Normalization (the core) ✅
- [x] Timestamps found by value anywhere in a row (ISO-8601/RFC3339 with offsets, epoch s/ms/µs/ns, FILETIME), normalized to fixed-width UTC; placeholder dates (1601/1970) and far-future values dropped.
- [x] One timeline event per distinct timestamp in a record, labelled with its source field(s) (MACB-style).
- [x] Structured fields for pivoting: user, process, command line, path, hash, IP, event ID.
- [x] Rows without timestamps (e.g. PSReadline) kept as records and reported by timeline queries, not dropped.
- [x] Event type from an ordered artifact-name table (Windows + Linux).
- [x] SQLite FTS5 (trigram) for case-insensitive substring search; LIKE fallback.
- [ ] Per-artifact refinements once real output is seen (e.g. Amcache date formats, better descriptions).

## Step 2b: Bounded collection ("triage first, targeted follow-ups") ✅
- [x] Case time window passed into each artifact's own date parameters (DateAfter/DateBefore, dateAfter...), so Velociraptor filters before sending.
- [x] Row limit per collection (`collection.max_rows`), sent to Velociraptor and enforced on ingest; truncated results flagged as incomplete.
- [x] Agent collections are targeted follow-ups: heavy artifacts (MFT, USN, EvtxHunter, file searches) need a filter; investigator approves each (`collection.agent_collections: confirm|auto|off`).
- [x] Search index holds short text per record instead of whole raw rows (was the main cause of multi-GB databases).

## Step 3: Query tools for correlation ✅
- [x] Every query returns total matches + "showing N of M".
- [x] `activity_histogram` — events per minute/hour/day and type, to find bursts.
- [x] `context_window(timestamp, ±minutes)` — what happened around an event, across all sources.

## Step 4: Report ✅
- [x] Report built from the database (`copilot/report.py`); the LLM only writes the executive summary, correlation analysis and recommendations.
- [x] Finding times derived from their evidence (not typed by the LLM); corrected UTC and recorded host time side by side (`scope.clock_offset_minutes`).
- [x] Evidence timeline of every cited record; per-finding evidence tables.
- [x] Correlations: LLM narrative plus computed links (shared evidence, within 15 minutes).
- [x] Indicators observed (IPs, accounts, processes, paths, hashes, command lines) from cited evidence; case IOC hit counts.
- [x] "Artifacts, locations & meanings" from a static reference (`copilot/knowledge.py`), also shown to the agent as artifact tips.
- [x] Markdown-safe cells, contiguous tables; collections and audit appendices.
- [x] Knowledge base in YAML (`copilot/knowledge_data/`): artifacts (verified params, live-only flag), event IDs, logon types, investigation playbooks; `dfir_guide` tool; event meanings annotated in the report.
- [x] Charts in the HTML report (static SVG, no scripts): activity over the window and a close-up of the intrusion with finding markers, findings sequence, finding-indicator connections; each with a data table, corrected times, dark mode.
- [ ] PDF export.

## Step 5: Agent core & UI
- [x] One agent loop (`run_turn`) shared by CLI and Streamlit, with token budget and wrap-up.
- [x] Streamlit: triage collection prompt/panel, Approve/Deny for agent collection requests, downloads in chat.
- [x] HTML report (self-contained, scripts blocked, evidence shown as text) next to Markdown.
- [x] Output directory for reports and exports (`DFIR_OUTPUT_DIR` / `output.dir`); CSV export of any query, JSON export of evidence records.
- [x] Multiple cases: per-case folders, database and outputs; switch with `/case`, the sidebar picker, or by asking; create cases from the chat or a form.
- [x] Approvals for every agent action with side effects (collect, retract, update/create/switch case): confirm | auto | off per action, per-case queue in Streamlit, y/N in CLI, audit-logged.
- [x] Login for the Streamlit app: local accounts (PBKDF2, lockout), works offline; approver recorded in the audit log.
- [x] Offline / local model: any OpenAI-compatible endpoint, no key for local ones, token estimate when usage isn't reported, Streamlit telemetry off.
- [x] Per-session active case for several simultaneous Streamlit users (own config and DB connection per session, WAL).
- [x] Cases bound to accounts: owner + members, admins see all, unowned cases admin-only; per-user chats; audit log records the investigator.
- [x] Server settings file (server.yaml) for the model, key and sign-in; environment variables still win.
- [x] Memory analysis with Volatility 3: plugin allowlist, memory triage, agent tool with approval, rows in the case DB, offline symbols (server.yaml memory:).
- [x] Lessons learned: the agent proposes, a person approves (admins with sign-in), shared by all cases on the server.
- [ ] Benchmark against answer keys (rows found, UTC times, no invented evidence).
- [ ] Prompt rewrite once the tools are stable.
- [ ] Report upload / sharing.

## Environment (outside this repo)
- [x] Dead-disk virtual client via `velociraptor deaddisk` remapping (E01 read directly, no admin) — documented in README.
- [ ] End-to-end run against a public practice image with a known answer key.
- [ ] Image hashing and read-only mount procedure recorded in the case file.
