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

## Step 2: Normalization (the core)
- [ ] Per-artifact mappers: UTC ISO-8601 timestamps (RFC3339 offsets, epoch, FILETIME), one timeline event per timestamp (MACB).
- [ ] Structured columns for pivoting: user, process, command line, path, hash, IP, event ID.
- [ ] Rows without timestamps (e.g. PSReadline) kept visible and labelled, not silently dropped from timelines.
- [ ] Event-type mapping per artifact instead of substring guessing.
- [ ] SQLite FTS5 for keyword search.

## Step 3: Query tools for correlation
- [ ] Every query returns total matches + "showing N of M".
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
- [~] Dead-disk virtual client via `velociraptor deaddisk` remapping — documented in README, verify against the server's Velociraptor version.
- [ ] Image hashing and read-only mount procedure recorded in the case file.
