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

2. **Present the image as a virtual client.** Mount the image read-only and
   generate a remapping for it with `velociraptor deaddisk` (check its flags with
   `velociraptor deaddisk --help` on your version). Then run the server and a client
   that uses the remapping (this is the local Windows test setup):
   ```powershell
   .\velociraptor.exe --config server.config.yaml frontend
   .\velociraptor.exe --config deaddisk_client.config.yaml --remap deaddisk.yaml client
   ```
   The image then appears as a client. Put its client ID in `case.yaml` under
   `velociraptor.client_id`. Windows and Linux images are both supported by the
   default artifact allowlist.

3. **Case file.** Edit `case.yaml`: incident window, IOCs, artifacts to
   auto-collect, and optionally which artifacts the agent may collect.

4. **LLM.** Set `OPENAI_API_KEY` (or enter it when prompted). Optional:
   `DFIR_LLM_MODEL`, `DFIR_LLM_BASE_URL`.

## Run

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
