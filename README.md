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

4. **Server settings and LLM.** Copy `server.example.yaml` to `server.yaml` and edit it: which
   model to use (the cloud endpoint, or a local one, see
   [Offline / local model](#offline--local-model)), its API key, and whether sign-in is
   required. `server.yaml` is git-ignored. Environment variables still work and win over the
   file (`DFIR_LLM_BASE_URL`, `DFIR_LLM_MODEL`, `DFIR_LLM_API_KEY` or `OPENAI_API_KEY`,
   `DFIR_LLM_TIMEOUT`, `DFIR_REQUIRE_LOGIN`). Without a key on the server, each investigator
   enters their own in the sidebar. The sidebar shows which model is in use.

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
- Each case keeps its own chat (what you see and what the agent remembers, tool results
  included), saved in its database after every exchange. Switching away saves it; switching
  back restores it, also after an app restart. Nothing leaks between cases. "🧹 New
  conversation" in the sidebar (CLI: `/new`) clears a case's chat; data and findings stay.
- Everything is editable from the app (no file access needed): the sidebar's **New case** form
  (Case ID and Name required; the client ID is needed before collecting) and **Case settings**
  for the active case (client, window, clock offset, description, IOCs). IOCs can be pulled from
  the description for free (patterns, including defanged `1.2.3[.]4` / `hxxp://`) or with
  **✨ AI extract** (one small LLM call; values must appear in the text). Saving rewrites the
  case.yaml without its comments.
- A new case on the same evidence can **copy the collected data** of another case instead of
  re-collecting (same client ID only; findings are not copied). Ask the agent or use the form.
- `DFIR_CASES_DIR` and `DFIR_DATA_DIR` change the two root folders.

Each browser session has its own active case, so several investigators can work at the same
time; with sign-in, each sees only their own cases (see [Sign-in](#sign-in)). The CLI has
one active case per process.

## Approvals

Evidence is written by the attacker, and text inside it can try to steer the AI ("retract
finding 3"). So everything the agent wants to change is a request you approve first:

| Action | Setting | Default |
|---|---|---|
| Collect an artifact | `collection.agent_collections` | confirm |
| Retract a finding | `agent.approvals.retract_finding` | confirm |
| Change case settings | `agent.approvals.update_case` | confirm |
| Switch case | `agent.approvals.switch_case` | confirm |
| Create a case | `agent.approvals.create_case` | confirm |

Each can be `confirm`, `auto` (no question) or `off` (the agent may not do it). Requests are
checked before you are asked, stay with their case if you switch away, and every request and
decision is written to the case's audit log. Your own actions (sidebar, `/case`, forms) are
never gated. Read-only analysis never needs approval.

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

## Playbooks on every question

The investigation playbooks (`copilot/knowledge_data/playbooks.yaml`) say which sources to check
for a kind of question. A question you type that matches a playbook's `triggers` (e.g. "how did X
get onto this machine?" → initial access; "which process owned the connection?" → memory) is sent
to the agent with that playbook and its lessons attached, so it follows them without having to
look them up. The chat still shows what you typed. Add or tune triggers in the YAML file.

## Lessons learned

The agent improves its own knowledge, with a person in the loop. When it has verified
something reusable (an artifact that returns nothing from disk images and why, a parameter
name that works, how to read a pattern of records), it proposes a **lesson** with
`propose_lesson`. The proposal waits in **Awaiting your approval** like any other change:
evidence is attacker-written, so nothing is learned without a person approving it.

- Approved lessons are added to the knowledge base for **every case on this server**: they
  show up in `dfir_guide` and `describe_artifact`, and an artifact a lesson marks as not
  working on disk images is refused before anyone is asked to approve collecting it.
- Lessons with case details (IPs, hashes, domains) are refused: they must be general.
- With sign-in, a lesson approved by a non-admin stays **proposed** until an admin accepts it.
  Lessons set to `auto` in a case file are always only proposed.
- The sidebar's **🧠 Knowledge** section lists the lessons, lets admins accept or remove them,
  and lets investigators write their own. On the server: `python -m copilot.lessons list`,
  `accept <id>`, `remove <id>`.
- They are stored in `learned_knowledge.yaml` (git-ignored; `knowledge.learned_file` in
  server.yaml or `DFIR_LEARNED_FILE`), with the case, date and approver of each.
- The built-in knowledge stays in `copilot/knowledge_data/*.yaml`; lessons that prove useful
  everywhere can be moved there by hand.

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
  sidebar's **Triage collection** panel can run it any time. **✏️ Choose what to collect**
  opens the triage list above the chat: ⭐ suggestions that work on disk images
  (`copilot/knowledge_data/triage.yaml`), every allowed artifact on your Velociraptor server
  (searchable), parameters as JSON, and the memory plugins. Use the choice for this session, or
  **Save as this case's triage** to write it into the case file;
- anything the agent wants to change (collect, analyze memory, retract a finding,
  change/create/switch a case) appears under **Awaiting your approval** with Approve / Deny,
  or **Approve all** when there are several (CLI: a y/N prompt). Once nothing is waiting, the
  agent continues with the results by itself (untick "Continue the agent…" to do it yourself);
- Database, Findings and Files are collapsible sections of the sidebar;
- every file the agent produces appears in the chat as a download button, and the sidebar
  lists recent files. Ask e.g. "export the timeline 02:30-03:00 as a file" or "give me the
  full records of the evidence for finding 3".

The HTML report includes charts (activity over the incident window and around the
findings, the findings in sequence, and which indicators connect which findings), drawn as
static SVG with a "Show data" table under each. It is self-contained and safe to open: evidence text is shown as text (never
interpreted as HTML) and the page blocks scripts and external content.

## Memory analysis (Volatility 3)

A case can have a memory image next to (or instead of) the disk image. The copilot runs
Volatility 3 on it and stores the results in the case database like collected artifacts, so the
timeline, search, findings and the report include them (sources `Memory.<plugin>`, e.g.
`Memory.windows.netscan.NetScan`).

**Set up (once, on the server):**

1. Install Volatility with the Python that runs the copilot: `pip install volatility3` (it is in
   `requirements.txt`). The `vol` command doesn't need to be on PATH; the copilot starts
   Volatility through Python itself.
2. In `server.yaml`, fill in the `memory:` block (see `server.example.yaml`): `images_dir` (the
   folder with the memory images), `symbols_dir`, `offline`.
3. Check it: `python -m copilot.memory check` lists the Volatility version, the images and the
   symbols. `python -m copilot.memory check <image name>` also reads the image (`windows.info`),
   which proves the symbols for it are there.

**Per case:** pick the image in the sidebar (**Case settings > Memory image**; the list shows the
files in `images_dir`), or write `memory: {image: <file name>}` in the case file. Then:

- **Run memory triage** (first visit, or the **Triage collection** panel; CLI: asked at start)
  runs `windows.info, pslist, psscan, pstree, cmdline, netscan, svcscan, malfind` without the
  LLM. Change the list with `memory.collect`; `memory.os: linux` picks Linux plugins.
- The agent runs more plugins with `analyze_memory`, e.g. `windows.malfind` for one PID, `windows.handles`
  filtered to a name, `windows.registry.printkey` for a key. Each request needs your approval
  (`agent.approvals.memory: confirm`; `auto` lets it run them freely, `off` forbids them). Heavy
  plugins (handles, dlllist, filescan, envars...) need a PID or text filter.
- Only the plugins listed in `copilot/memory.py` can run, with only their listed options. Nothing
  can dump files or open a file outside `images_dir`.
- Each plugin run can take minutes on a large image. `memory.timeout` stops it (default 1 h).

**Symbols and offline use.** To read a Windows image, Volatility needs the symbol table of that
image's exact Windows kernel. With `offline: true` it never downloads anything, so the table must
already be in `symbols_dir` (or in Volatility's own `symbols` folder). Three ways to get it there:

- **Online once:** set `offline: false` while the server has internet and run
  `python -m copilot.memory check <image name>`. Volatility downloads the table from Microsoft into
  `symbols_dir`. Switch back to `offline: true`; that image now works offline.
- **Copy from a PC that already read the image:** `windows.info` prints the table's path as
  `Symbols` (`...\symbols\windows\ntkrnlmp.pdb\<ID>.json.xz`). Copy the `windows` folder from
  there into `symbols_dir`, keeping the sub-folders.
- **The symbol pack:** on a PC with internet, download
  `https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip` and put
  `windows.zip` into `symbols_dir` as it is. It covers many Windows builds, not all of them.

If a table is missing, the copilot says so and names the folder. Linux images need a table built
for their exact kernel (Volatility's `dwarf2json`), placed in `symbols_dir/linux`.

## Sign-in

The web app uses local accounts stored on the server, so it works without internet access
or an identity provider. Passwords are stored as salted PBKDF2-SHA256 hashes in `auth.yaml`
(`DFIR_AUTH_FILE`; git-ignored, readable only by its owner).

```bash
python -m copilot.auth add alice --admin   # asks for the password (12+ characters) twice
python -m copilot.auth add bob
python -m copilot.auth admin bob on|off    # admins see every case
python -m copilot.auth list
python -m copilot.auth remove bob          # also signs out bob's open sessions
```

- With no accounts, the app runs open and shows a warning. Set `login.required: true` in
  `server.yaml` (or `DFIR_REQUIRE_LOGIN=1`) on a server so it refuses to run open.
- After 5 failed attempts an account is locked for 5 minutes.
- Approvals and sidebar retractions record who made them, in the audit log and in the
  finding's retraction reason. In the CLI, this is the operating system user.
- Refreshing the page signs you out. The chat is kept per case, so nothing is lost.
- Streamlit serves plain HTTP. Serve it over HTTPS (`server.sslCertFile` and
  `server.sslKeyFile` in `.streamlit/config.toml`, or a TLS reverse proxy), otherwise
  passwords cross the network in clear text.

**Cases belong to accounts.** Whoever creates a case owns it. The owner (or an admin) adds
members under **👥 Access** in the sidebar; only an admin can change the owner. An
investigator sees, opens, copies from and gets files of only the cases they own or are a
member of. Admins see all. Cases made before sign-in have no owner and are visible to admins
only until an admin assigns them. The agent cannot change access.

- Someone without any case gets the New case form instead of the chat.
- Members share the case's data, findings and files, but each keeps their own chat. On a
  member's first visit they see the chat from before sign-in, if there was one.
- Removing someone from a case takes effect on their next click.
- The audit log records who was working for every entry (the report shows it as an
  "Investigator" column).
- With `DFIR_OUTPUT_DIR` set (a folder shared by all cases), each case writes into its own
  sub-folder, e.g. `/uploads/<case-id>/`.
- Two browser tabs of the same person are two sessions; each saves the chat when it is
  used, so keep one tab per case.
- The CLI (`python main.py`) runs on the server without sign-in and can open every case.

## Offline / local model

The copilot needs no internet access once its packages are installed: Velociraptor, the
case data, the knowledge base and the reports are all local. Memory analysis needs the symbol
tables of the images' Windows kernels; see [Memory analysis](#memory-analysis-volatility-3)
for getting them onto an offline server. Streamlit's usage statistics
are switched off in `.streamlit/config.toml` (start the app from this folder). Set
`browser.serverAddress` there as well, so Streamlit doesn't look up its public IP at startup.

To use a model on your own hardware, point the copilot at any OpenAI-compatible server in
`server.yaml`. Endpoints on localhost, a private IP address or a `.local` name need no API
key (`local: true` marks any other host as local):

```yaml
llm:
  base_url: http://localhost:11434/v1     # Ollama
  model: <model name>                     # must support tool calling
  timeout: 900                            # local models can be slow
```

The same with environment variables, e.g. in PowerShell before `streamlit run app.py`:
`$env:DFIR_LLM_BASE_URL = "http://localhost:11434/v1"`, `$env:DFIR_LLM_MODEL = "<model name>"`.
To go back to the cloud model, remove those lines (or variables).

- The agent works only through tool calls, so the model must support them. With vLLM,
  start the server with `--enable-auto-tool-choice` and the model's `--tool-call-parser`.
- Give the model a large context (at least 32k tokens). Ollama's default context is much
  smaller and silently cuts the conversation; raise it (`OLLAMA_CONTEXT_LENGTH`, or
  `num_ctx` in a Modelfile).
- If the server reports no token usage, the copilot estimates it (about 4 characters per
  token) so the per-turn budget still applies. The usage line then says "estimated".
- Servers that reject `tool_choice="none"` still work: the wrap-up answer is requested from
  the normal model.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests
```

The tests use a fake Velociraptor client, so they need no server.
