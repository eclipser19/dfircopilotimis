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

## Step 3: Query tools for correlation
- [x] Every query returns total matches + "showing N of M".
- [ ] Aggregations (events per hour / source / user) to find activity bursts.
- [ ] `context_window(timestamp, ±minutes)` — what happened around an event, across all sources.

## Step 4: Report
- [ ] Event timeline section (not just findings), with evidence excerpts per finding.
- [ ] "Artifacts, locations & meanings" section from a static reference table.
- [ ] Correlations section; IOC hit counts not capped.
- [ ] Markdown escaping of evidence text; HTML/PDF output.

## Step 5: Agent core & UI
- [ ] One agent loop shared by CLI and Streamlit (the loop is still duplicated in `app.py`).
- [ ] Prompt rewrite once the tools above are stable.
- [ ] Report upload / sharing.

## Environment (outside this repo)
- [x] Dead-disk virtual client via `velociraptor deaddisk` remapping (E01 read directly, no admin) — documented in README.
- [ ] End-to-end run against a public practice image with a known answer key.
- [ ] Image hashing and read-only mount procedure recorded in the case file.
