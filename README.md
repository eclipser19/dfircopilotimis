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

Case data (database, reports, exports) goes to `case_data/`, or to
`DFIR_CASE_DIR` if set.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests
```

The tests use a fake Velociraptor client, so they need no server.
