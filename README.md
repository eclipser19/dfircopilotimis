# DFIR Copilot

An LLM agent that investigates a forensic disk image through Velociraptor, keeps
everything it collects in a local SQLite case database, records findings with
evidence references, and produces a DFIR report. See `PLAN.md` for status.

## Setup

```bash
pip install -r requirements.txt
```

1. **Velociraptor API access.** Create an API client config and save it as
   `api_client.yaml` (git-ignored), or point `DFIR_API_CONFIG` at it:
   ```bash
   velociraptor --config server.config.yaml config api_client --name dfir_copilot --role investigator api_client.yaml
   ```
   Use the `investigator` role, not `administrator`. That role can collect
   artifacts but has no server command execution or filesystem write permission,
   which is the real safety net behind the agent's own allowlists.

2. **Present the image as a virtual client.** Velociraptor (0.7.2+) reads E01
   images directly, so nothing needs to be mounted and no admin rights are needed.
   Point `deaddisk` at the first segment (`.E01`; the other segments must be in the
   same folder) and run a client with the generated remapping:
   ```powershell
   .\velociraptor.exe deaddisk --add_windows_disk=D:\evidence\image.E01 deaddisk.yaml -v
   .\velociraptor.exe --config server.config.yaml frontend
   .\velociraptor.exe --config deaddisk_client.config.yaml --remap deaddisk.yaml client
   ```
   The image then appears as a client. Put its client ID in `case.yaml` under
   `velociraptor.client_id`. Check `deaddisk --help` on your version for other
   options (e.g. Linux images). Avoid remapping a live drive (`file_nocase` on
   `C:\`): running Windows keeps event logs, registry hives and `$MFT` locked, so
   most artifacts come back empty.

3. **Case file.** Edit `case.yaml` (or use another file via `DFIR_CASE_FILE`):
   incident window, IOCs, triage artifacts to auto-collect, and limits.
   How collection works:
   - The `collect:` list runs first, without the LLM. The incident window is passed
     into each artifact's own date filters, and each collection is capped at
     `collection.max_rows` rows.
   - The agent then analyzes the case database. If it needs more data it asks for a
     targeted collection; heavy artifacts (MFT, USN, EvtxHunter) need a filter, and
     with `agent_collections: confirm` you approve each request (y/n).
   See `cases/szechuan/` for a complete example with an answer key.

4. **LLM.** Set `OPENAI_API_KEY` (or enter it when prompted). Optional:
   `DFIR_LLM_MODEL`, `DFIR_LLM_BASE_URL`.

## Cases

Each investigation is a folder with its own settings, database and outputs:

```
cases/<case-id>/case.yaml        settings (scope, client ID, IOCs, triage list, limits)
case_data/<case-id>/case.db      collected data, findings, audit log
case_data/<case-id>/outputs/     reports and exports (unless output.dir is set)
```

- Start in a case: `$env:DFIR_CASE = "szechuan"` (or `DFIR_CASE_FILE` with a path). Without
  either, the legacy root `case.yaml` with `case_data/case.db` is used (listed as `default`).
- Switch in the chat with free commands (no LLM): `/cases`, `/case <id>`, `/help`. Or ask in
  words ("switch to the szechuan case", "create a case for host X"). In Streamlit there is
  also a case picker and a "New case" form in the sidebar.
- Switching starts a fresh conversation, so nothing from one case leaks into another.
- Everything is editable from the app (no file access needed): the sidebar's **New case** form
  (Case ID and Name required; the client ID is needed before collecting) and **Case settings**
  for the active case (client, window, clock offset, description, IOCs). IOCs can be pulled from
  the description for free (patterns, including defanged `1.2.3[.]4` / `hxxp://`) or with
  **✨ AI extract** (one small LLM call; values must appear in the text). Saving rewrites the
  case.yaml without its comments.
- A new case on the same evidence can **copy the collected data** of another case instead of
  re-collecting (same client ID only; findings are not copied). Ask the agent or use the form.
- `DFIR_CASES_DIR` and `DFIR_DATA_DIR` change the two root folders.

The active case is process-wide: run one Streamlit app per investigator.

## Knowledge base

`copilot/knowledge_data/` holds the DFIR reference the copilot relies on, as plain YAML
you can extend without touching code:

| File | Contents | Used by |
|---|---|---|
| `artifacts.yaml` | Where each artifact's data lives, what it proves, verified parameter names, tips, live-only flag | Report "Artifacts, locations & meanings"; `describe_artifact`; live-only artifacts are refused on images |
| `event_ids.yaml` | Windows event IDs per log channel, with notes | Report annotations and "Event IDs referenced"; `dfir_guide` |
| `logon_types.yaml` | 4624 LogonType values | Report annotations |
| `playbooks.yaml` | For each investigation question, which sources to check | `dfir_guide` |

Patterns in `artifacts.yaml` are matched in order (first match wins), so put specific
entries above general ones. Only list parameter names under `params` once a real
collection has confirmed them.

## Run

Check the Velociraptor side first (no LLM involved): connection, the case's
client, artifact lookup, and one real collection.

```bash
python -m copilot.selftest
```

Then:

```bash
python main.py          # terminal
streamlit run app.py    # web chat
```

The case database lives in `case_data/` (or `DFIR_CASE_DIR`). Reports are written as HTML
by default; set `output.report_formats: [html, md]` in the case file for Markdown too (the
second format costs no LLM tokens), or pick formats in the Streamlit sidebar. The agent
cannot choose the format. Files the
copilot produces (reports, case exports, CSV exports of query results, JSON evidence
extracts) go to the output directory: `DFIR_OUTPUT_DIR`, else `output.dir` in the case
file (e.g. `/uploads` on a server), else `case_data/outputs/`.

In the Streamlit app:
- an empty case offers the triage collection (same as the CLI's first question), and the
  sidebar's **Triage collection** panel can run it any time;
- collections the agent asks for appear under **Collection requests** with Approve / Deny;
- every file the agent produces appears in the chat as a download button, and the sidebar
  lists recent files. Ask e.g. "export the timeline 02:30-03:00 as a file" or "give me the
  full records of the evidence for finding 3".

The HTML report is self-contained and safe to open: evidence text is shown as text (never
interpreted as HTML) and the page blocks scripts and external content.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests
```

The tests use a fake Velociraptor client, so they need no server.
