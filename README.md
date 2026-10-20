# DFIR Copilot

An LLM agent that investigates a forensic disk image through Velociraptor (and a memory image
through Volatility 3), keeps everything it collects in a local SQLite case database, records
findings with evidence references, and produces a DFIR report.

Status and next steps: [PLAN.md](PLAN.md). Measured results: [BENCHMARKS.md](BENCHMARKS.md).
Working on the code: [CONTRIBUTING.md](CONTRIBUTING.md) and [CLAUDE.md](CLAUDE.md).

## Quick start

From a fresh clone to a first answer. Each step is explained under [Setup](#setup).

1. `pip install -r requirements-lock.txt` (Python 3.10 to 3.12; the lock file holds the exact tested
   versions, `requirements.txt` the minimums).
2. Run a Velociraptor server (0.77.2 is the version tested) and save an API client config with the
   `investigator` role as `api_client.yaml` ([Setup](#setup) step 1).
3. Present the image as a client with `velociraptor deaddisk` and start that client; note its
   client ID (step 2).
4. `copy server.example.yaml server.yaml` (`cp` on Linux) and set the model and API key. Create
   your account: `python -m copilot.auth add <you> --admin`.
5. Check the Velociraptor side without the model: `python -m copilot.selftest`.
6. `streamlit run app.py`, sign in, create a case in the sidebar (**New case**: ID, name, client
   ID, incident window), run the triage it offers, then ask a question, e.g. "How did the attacker
   get in?". The terminal version is `python main.py`.

`cases/szechuan/case.yaml` is a complete example case file. The benchmarks in `cases/` show what
to expect, with answer keys.

## Setup

```bash
pip install -r requirements-lock.txt     # the exact versions the tests run with (Python 3.10-3.12)
```

`requirements.txt` lists the same packages with minimum versions only. Check your settings files
at any time: `python -m copilot.config_check` names unknown or misspelt settings and values of the
wrong type in `server.yaml` and every case file (the app and the CLI show them too).

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
   options (e.g. Linux images). A logical image (AD1) or a folder of collected files works too:
   open it as a folder (FTK Imager mount or export) and use `--add_windows_directory=<folder that
   holds Windows and Users>`. Avoid remapping a live drive (`file_nocase` on
   `C:\`): running Windows keeps event logs, registry hives and `$MFT` locked, so
   most artifacts come back empty.

3. **Case file.** Edit `case.yaml` (or use another file via `DFIR_CASE_FILE`):
   incident window, IOCs, triage artifacts to auto-collect, and limits.
   How collection works:
   - The `collect:` list runs first, without the LLM. The incident window is passed
     into each artifact's own date filters, and each collection is capped at
     `collection.max_rows` rows.
   - The agent then analyzes the case database. If it needs more data it asks for a
     targeted collection; heavy artifacts (MFT, USN, EvtxHunter) need a filter, parameter
     names must be ones the artifact declares (Velociraptor silently ignores others), and
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

Each investigation is one folder, named by its case ID, with its settings and its data:

```
cases/<case-id>/case.yaml          settings (scope, client ID, IOCs, triage list, limits)
cases/<case-id>/data/case.db       collected data, findings, chats, audit log
cases/<case-id>/data/outputs/      reports and exports (unless output.dir is set)
```

`data/` holds evidence and is git-ignored; `case.yaml` is not. Data from before this layout
(`case_data/<case-id>/`) is still read where it is; move it into the case folders once, with the
app and the CLI stopped:

```bash
python -m copilot.cases move-data          # shows what would move
python -m copilot.cases move-data --yes    # moves it
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
  (Case ID and Name required; the client ID is needed before collecting) and the **⚙️ Case** tab
  for the active case (client, window, clock offset, description, IOCs). IOCs can be pulled from
  the description for free (patterns, including defanged `1.2.3[.]4` / `hxxp://`) or with
  **✨ AI extract** (one small LLM call; values must appear in the text). Saving rewrites the
  case.yaml without its comments.
- A new case can **start from another case's data** instead of re-collecting: it gets that case's
  evidence (client and memory image) and a copy of its collected data, and optionally its findings
  and dossier (copied findings say which case they came from). **Case settings → Import from another
  case** does the same for an existing case on the same evidence. Ask the agent or use the forms.
  The source can be one of your cases or one shared with you (see [Sign-in](#sign-in)).
- `DFIR_CASES_DIR` changes the cases folder. `DFIR_DATA_DIR` keeps the data apart instead, in
  `<DFIR_DATA_DIR>/<case-id>/` (e.g. on a larger disk).

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
decision is written to the case's audit log. Your own actions (buttons, `/case`, forms) are
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
| `forensic_artifacts.yaml` | Where Windows and applications keep ~350 kinds of data (file globs, registry keys), converted from [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) (Apache-2.0, `forensic_artifacts.LICENSE`) | `find_data_location`: returns ready `Windows.Search.FileFinder` / `Windows.Registry.NTUser` parameters |

Patterns in `artifacts.yaml` are matched in order (first match wins), so put specific
entries above general ones. Only list parameter names under `params` once a real
collection has confirmed them.

`forensic_artifacts.yaml` is generated; don't edit it. To update it, check out the
ForensicArtifacts repository and run `python -m copilot.forensic_artifacts import <checkout>`.
Placeholders become globs for an image mounted as C: (`%%users.homedir%%` -> `C:\Users\*`,
CurrentControlSet -> ControlSet001); WMI and command sources (live systems only) are dropped.

## Playbooks on every question

The investigation playbooks (`copilot/knowledge_data/playbooks.yaml`) say which sources to check
for a kind of question. A question you type that matches a playbook's `triggers` (e.g. "how did X
get onto this machine?" → initial access; "which process owned the connection?" → memory) is sent
to the agent with that playbook and its lessons attached, so it follows them without having to
look them up. The chat still shows what you typed. Add or tune triggers in the YAML file.

## Teaching the copilot as you use it

Every answer can be corrected, and the copilot keeps what it is told:

- **👎 under each answer** (and under the dossier) asks what is wrong and what is right; that
  correction becomes a **note** of the case. CLI: `/wrong <what is right>` corrects the last answer.
- **Notes** (🚩 Findings & dossier tab, or `/note <text>`, `/notes`, `/notes remove <n>` in the chat):
  facts and corrections the copilot takes as given in this case. Every conversation and investigation
  of the case gets them, above the dossier; when evidence contradicts one, the copilot says so instead
  of overriding it. "Investigate again" builds the next dossier on them. Other members of the case get
  them with their next question.
- **Confirm a finding** (✅ in its row) once you have checked its records: the copilot treats it as
  established, and the report shows who confirmed each finding ("Review" line, "Confirmed" column).
  Retract the ones the data contradicts.
- **A correction that holds for every case** (how to read an artifact or a kind of record, never a fact
  of this case) can also be proposed as a lesson from the 👎 form; an admin accepts it (see below).
- **For whoever improves the copilot**: `python -m copilot.feedback list` (counts per case) and
  `python -m copilot.feedback export` write every note, correction and confirmed finding, with its question
  and answer, to `feedback_exports/` (git-ignored: answers quote evidence). Corrected answers are the
  best source of new benchmark questions and of fixes to playbooks and prompts (see CONTRIBUTING).

Everything is written to the case's audit log with who did it.

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

The case database lives in the case's `data/` folder (see [Cases](#cases)). Reports are written as HTML
by default; set `output.report_formats: [html, md]` in the case file for Markdown too (the
second format costs no LLM tokens), or pick formats in the app's **📄 Report & files** tab. The agent
cannot choose the format. Files the
copilot produces (reports, case exports, CSV exports of query results, JSON evidence
extracts) go to the output directory: `DFIR_OUTPUT_DIR`, else `output.dir` in the case
file (e.g. `/uploads` on a server), else the case's `data/outputs/`.

**Investigate once, then answer.** After the triage, the agent investigates the whole case in
one longer turn (40 tool steps by default) and writes the **case dossier**: the intrusion
timeline, its findings, key entities, hypotheses, contradictions and gaps, with evidence IDs.
The dossier is stored in the case and goes into every later conversation, so each question starts
from it and only checks what it adds. Answers then agree with each other, and a question costs a
fraction of re-investigating the case. It is optional: questions work without it. In the app the
checkbox **Then investigate the case (optional)** sits next to the triage buttons (ticked by
default; untick it to look at the data first). The first-visit **Run triage (disk + memory)** runs
both triages and then one investigation. A case with data but no dossier shows an **Investigate
now / Not now** card, and the **🚩 Findings & dossier** tab shows the dossier and runs it
(again, e.g. after new data). In the CLI it is offered after the triage, and `/investigate` runs it
in either. Running it again starts from the previous dossier and replaces
it; every member of the case gets the new one with their next question. Its budget is
`agent.investigate_steps` / `agent.investigate_tokens` in the case file (default: twice a
question's). Requests it makes (collections, memory runs) wait for approval as usual; their
results go to the chat, so investigate again to fold them into the dossier.

In the Streamlit app, the page shows the open case at a glance: its name, its evidence (client
ID, host name, disk image file, memory image), the incident window and clock offset, how much data
it holds, and its findings and dossier. Below are one tab per job:
- **💬 Chat**: ask the copilot. The question box stays at the bottom of every tab, and work started
  anywhere (triage, investigation, the report, approvals) opens this tab, where it runs. An empty
  case offers the triage here (same as the CLI's first question).
- **🚩 Findings & dossier**: the case dossier (and **Investigate**), every finding with its true
  UTC and recorded time, confidence, MITRE technique, origin and the records behind it, and
  **Retract a finding**.
- **📥 Evidence & data**: the evidence sources with their hashes, the triage (**✏️ Choose what to
  collect** opens the list: ⭐ suggestions that work on disk images, every allowed artifact on your
  Velociraptor server, parameters as JSON, the memory plugins; use it for this session or **Save
  as this case's triage**), every collection with its state, and **Search the data**: any text,
  IP, account, file name or hash over all records, without the LLM.
- **📄 Report & files**: report formats, **Write the report** (the agent writes the narrative),
  and every file produced for the case as a download.
- **⚙️ Case**: settings, importing from another case, access and sharing.

The sidebar holds the case picker, **New case**, **New conversation**, the token count, and
anything the agent wants to change (collect, analyze memory, retract a finding,
change/create/switch a case) under **Awaiting your approval** with Approve / Deny, or **Approve
all** when there are several (CLI: a y/N prompt). Once nothing is waiting, the agent continues with
the results by itself (untick "Continue the agent…" to do it yourself). Files the agent produces
also appear in the chat as download buttons: ask e.g. "export the timeline 02:30-03:00 as a file"
or "give me the full records of the evidence for finding 3".

The agent is told to correlate before it claims: who, from where, that something ran, or that
one event caused another needs a second record that agrees (a logon's own source IP, the same
logon ID, path or hash), and it says when a claim rests on one record. A finding recorded as
"high" confidence with only one record (or the same event collected twice) is saved as "medium".

Before the model reads anything, the data is summarised without it: the case summary every
question starts with lists leads with their evidence IDs. They cover logons grouped by source
address (failures, successes, accounts, logon types, workstation names, and guessing that worked),
account and group changes, services installed, scheduled tasks with stored passwords or commands in
user folders, log clearing and Defender events, downloads by origin, and programs in user folders.
`logon_summary` gives every logon source on request. This replaces dozens of searches through
hundreds of thousands of logon events, and keeps the answers to different questions consistent.

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

**Per case:** pick the image in the **⚙️ Case** tab (**Memory image**; the list shows the
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

**Searching memory.** When an IP, domain, URL or file name shows up nowhere in the collected data,
the agent can search the memory image for it (with your approval, like any plugin):

- `strings` reads the image file itself for the text, as ASCII and UTF-16, and stores each place
  with the readable text around it (a full URL, an HTTP request). It also finds leftovers in freed
  memory of processes that have exited. It needs neither Volatility symbols nor YARA, but it
  can't say which process the memory belonged to, and it can't see inside compressed images.
  With `words` (up to 20 texts) it searches for all of them in one pass, e.g. the names of
  command-line utilities, so every command line they appear in comes back with the rest of its
  line (about 25 s per GB for 20 words).
- `windows.memsearch` searches each running process's memory: with `text` it names the processes
  that still hold the text, with the text around it (e.g. the owner of a C2 address that netscan
  could not read); with `rules` it scans with a YARA rule file from `memory.yara_dir`. The agent
  can't write rules itself; it can only use the files in that folder. It is the copilot's own
  Volatility plugin (`copilot/vol_plugins/`), sturdier than `windows.vadyarascan`: an unreadable
  process or region is skipped instead of stopping the run. Text searches need nothing extra;
  rules need YARA for Python next to Volatility: `pip install yara-x` (or `yara-python`).
  `python -m copilot.memory check` says whether it is available. (Linux: `linux.vmayarascan`.)

Searches need a text or rules, so they can't be part of the memory triage.

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
members under **👥 Access** in the **⚙️ Case** tab; only an admin can change the owner. An
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

**Evidence belongs to cases too.** A case reaches evidence through its Velociraptor client ID
and its memory image, so those are protected, not only the case folders:

- A new or edited case may name a client or memory image only if no case uses it yet, or if
  you can open one of the cases that use it. Otherwise it is refused ("evidence in an
  investigation you are not part of"): ask that case's owner to add you. Admins may name any.
  The memory image picker lists only the images you may use.
- `login.new_evidence: admins` in `server.yaml` keeps evidence no case uses yet for admins:
  an admin opens the first case on each image and adds the investigators.
- Once a case holds data from a client or memory image, that setting is locked (greyed out
  in **Case settings**). Pointing the case at other evidence would mix two machines in one
  database: create a new case instead. Copying data between cases checks where the data
  came from, not only the settings.
- An agent collection or memory run waiting for approval runs only if the case still points
  at the evidence it was asked for. If another member changed it meanwhile, approving it
  does nothing and says so.

**Sharing a case's evidence.** The owner (or an admin) can share a case under **👥 Access → Share
its evidence** with chosen accounts or with everyone on the server, with or without its findings
and dossier. Those people can start their own case from it (**New case → Start from another case's
data**) or import it into one of theirs, and may use its client and memory image. They can't open
the shared case, its chats, files or audit log; members are still needed for that. Each copy is
written to both cases' audit logs, so the owner sees who started from their case. Stopping the
sharing prevents new copies; cases already started from it keep their copy and their evidence.

**Provenance in the report.** Section 2 lists each evidence source the data came from: the
client (with the host name Velociraptor reports, and the disk image's file name and SHA-256
entered under **Case settings** or in `case.yaml`'s `evidence:` section), each memory image
with its size and SHA-256, how many collections and rows came from each, and when. The
copilot hashes a memory image itself on its first Volatility run (a large image adds some
seconds to that run, once); if the file changes later, the report warns that it has two
hashes. A report whose records come from more than one disk client says so.

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

## Benchmark

Scores the copilot on an image with a known answer key, so changes to prompts, knowledge or
the model can be compared run against run. The checks are done in code (free, repeatable):

```bash
python -m copilot.benchmark run cases/szechuan-dc/benchmark.yaml --client C.<id of the image's client>
python -m copilot.benchmark run <spec> --from-case <case id>   # start from an earlier run's triage, no collecting
python -m copilot.benchmark run <spec> --questions entry,malware
python -m copilot.benchmark run <spec> --no-investigate        # questions without the case dossier first
python -m copilot.benchmark score benchmark_results/<run>.json # score saved answers again (key corrected)
python -m copilot.benchmark clean --yes                        # remove the bench-* run cases
```

Each run creates a fresh case `bench-<name>-<time>` from the spec's case file (agent collections
and memory runs approved automatically; case changes and lessons off), runs the triage without
the LLM, runs the investigation that writes the case dossier (as the app does after triage; its
steps, tokens and time count in the totals, and the scorecard shows the dossier), then asks every
question in a fresh conversation that starts from the dossier. `--no-investigate` skips the
investigation, as runs did before it existed; `--questions none` (a triage-only case) skips it
too.

**Saving time between runs.** The triage is the slow part (Velociraptor on a large image, the
memory triage). `--from-case <an earlier run of the same image>` starts from that run's triage
instead: only what was collected before its agent's first own collection is copied (so the run is
comparable, not helped by what the last agent found; `--all-data` copies everything), the client and
memory image come with it, and triage artifacts it lacks (e.g. added to the case file since) are
collected. A copy takes seconds. The run also checks the model (and asks for its key) before
anything else, records the commit it ran on, and flags times in answers that none of their cited
records holds. Per question it records the answer,
tool calls, steps, tokens and time, and scores each expected fact:
- **found:** the answer has the fact's words (`all`, one of each `any` group, `regex`);
- **time:** a true-UTC time in the expected range near those words; a recorded (host clock)
  time given as UTC counts as an *uncorrected time*;
- **citations:** evidence and finding IDs that don't exist in the case;
- **forbidden claims:** e.g. another host's events.

A run waits up to `--triage-wait` minutes (default 60) for triage collections still running, so
every run starts from the same data; if one never finishes, the scorecard says so under Setup.
The scorecard is written to `benchmark_results/<run>.json` and `.md`. The questions and answers
are also the run case's chat, so you can open the run in the app. Benchmarks:
- `cases/szechuan-dc/`: the Szechuan Sauce domain controller (disk + memory, intrusion). Its first
  runs were used to fix the knowledge, so it is no longer fully blind.
- `cases/corporatesecrets/`: CyberDefenders "CorporateSecrets" (disk only, insider / HR case),
  held out. It comes as an AD1 logical image: `answer_key.md` explains how to present it to
  Velociraptor as a folder (`deaddisk --add_windows_directory`).
- `cases/injector/`: CyberDefenders "Injector" (raw disk + memory, web server breached through
  its web application). Its runs led to the web-attack knowledge, so it is no longer fully blind.
- `cases/ou-server2022/`: Open University "Compromised Windows Server 2022 (simulation)" (E01,
  RDP and ransomware). There is no published solution: the key was built from a blind run's
  cited records, Hayabusa rules and reference lookups (`answer_key.md`). That run's mistakes led
  to generic fixes (correlation rule, accounts and impact playbooks), so it is no longer blind.

The desktop case (`cases/szechuan/`) was used to tune the knowledge, so it isn't a fair test.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests
```

The tests use a fake Velociraptor client, so they need no server.
