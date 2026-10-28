# Deploying DFIR Copilot on a Windows forensic machine

One Windows machine runs everything; investigators use the web app from their own computers over
HTTPS. The model is reached over the internet (any OpenAI-compatible endpoint). `README.md` explains
each piece in depth; this file is the order to do it in and what to keep safe.

```
Investigators' browsers ──HTTPS :8501──▶ Streamlit app (app.py, Python)
                                            │  gRPC 127.0.0.1:8001 (API, investigator role)
                                            ▼
                                   Velociraptor server (frontend :8000 and GUI :8889, local only)
                                            ▲
                       one dead-disk client per image (velociraptor client --remap)
                                            │ reads
                                   D:\evidence\<image>.E01      Volatility 3 reads D:\memory\<image>.mem
```

Only port 8501 is opened to the network. Velociraptor's ports stay on 127.0.0.1.

## 1. Install

1. **Python 3.12** (CI tests 3.10 to 3.12; the suite also passes on 3.13). Make a virtual environment
   next to the code and install the exact tested versions:
   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements-lock.txt
   pip install pytest; python -m pytest tests      # optional check: about 3 minutes, no Velociraptor needed
   ```
2. **Velociraptor 0.77.2** (the version tested): `velociraptor-v0.77.2-windows-amd64.exe` from
   github.com/Velocidex/velociraptor/releases, saved as `velociraptor.exe` next to the code (git-ignored).
3. **Volatility symbols** for memory images (offline use): see README "Memory analysis".

## 2. Velociraptor server and API

```powershell
.\velociraptor.exe config generate -i                 # once: answer the questions, writes server.config.yaml
.\velociraptor.exe --config server.config.yaml config api_client --name dfir_copilot --role investigator api_client.yaml
.\velociraptor.exe --config server.config.yaml config client | Out-File -Encoding ascii client.config.yaml
.\velociraptor.exe --config server.config.yaml frontend
```

- In `server.config.yaml`, set `Frontend.bind_address`, `API.bind_address` and `GUI.bind_address` to
  `127.0.0.1`: only the copilot and the dead-disk clients on this machine use them. The generator puts the
  frontend on `0.0.0.0` (every network).
- **Move the datastore out of a temp folder.** `Datastore.location` and `Datastore.filestore_directory`
  default to `C:\Windows\Temp` on Windows, which Windows cleans up. Point both at a kept folder (e.g.
  `C:\dfir\velociraptor-data`) before the first case, and back it up (section 6).
- PowerShell's `>` writes UTF-16; Velociraptor reads it, but `Out-File -Encoding ascii` keeps the files plain.
- `investigator` is the right role for `api_client.yaml`: it can collect but not run commands on the server.
- `server.config.yaml` holds the Velociraptor CA's private key, `api_client.yaml` a client key: both are
  git-ignored and belong in the backup (section 6), nowhere else.

## 3. One dead-disk client per image

Each image becomes its own Velociraptor client. **Give each image its own client config with its own
writeback file**: the writeback is the client's identity, so two images sharing one also share one client
ID, and the copilot then treats them as the same evidence (access checks, locks, reports).

```powershell
copy client.config.yaml deaddisk-<case>_client.config.yaml
#   edit Client.writeback_windows in the copy: deaddisk-<case>.writeback.yaml
.\velociraptor.exe deaddisk --add_windows_disk=D:\evidence\<image>.E01 deaddisk-<case>.yaml -v
.\velociraptor.exe --config deaddisk-<case>_client.config.yaml --remap deaddisk-<case>.yaml client
```

- E01: point at the first segment, the others in the same folder. Raw images work the same way.
- A logical image (AD1) or a folder of collected files: mount or export it as a folder (FTK Imager) and use
  `--add_windows_directory=<folder holding Windows and Users>`. Never remap the machine's own `C:\`.
- The client shows up in the Velociraptor GUI (and to admins in the copilot): its ID (`C.…`) goes into
  the case. Keep the evidence read-only (file attribute or a read-only share): the copilot never writes to it.
- `*.writeback.yaml` and the `.bak` next to it hold the client's key and state: keep them (backup), never commit them.

## 4. The copilot

1. `copy server.example.yaml server.yaml` and set the model (`llm`) and its API key. The example's
   defaults are the ones for a shared server: `login.required: true`, `login.new_evidence: admins` (an
   admin opens the first case on each image and adds the investigators), `report.confirmed_findings_only:
   true` (reports carry only findings an investigator confirmed). Memory: `memory.images_dir`, `symbols_dir`.
2. Accounts (12+ character passwords; 5 failures lock an account for 5 minutes):
   ```powershell
   python -m copilot.auth add <admin> --admin
   python -m copilot.auth add <investigator>
   ```
3. Check everything without the model:
   ```powershell
   python -m copilot.config_check          # server.yaml and every case file
   python -m copilot.selftest              # Velociraptor connection, a client, one real collection
   python -m copilot.memory check          # Volatility, symbols, YARA, memory images
   ```

## 5. HTTPS and network access

Passwords are sent at sign-in, so the app must not be served over plain HTTP to other computers.

1. Get a certificate for the machine's name from your company PKI (a self-signed one works, but every
   browser warns). Put the PEM files outside the code folder.
2. In `.streamlit/config.toml`:
   ```toml
   [browser]
   gatherUsageStats = false
   serverAddress = "<machine name investigators use>"

   [server]
   headless = true
   address = "0.0.0.0"
   port = 8501
   sslCertFile = "C:/dfir/tls/cert.pem"
   sslKeyFile = "C:/dfir/tls/key.pem"
   ```
3. Open the port on the domain network only (admin PowerShell):
   ```powershell
   New-NetFirewallRule -DisplayName "DFIR Copilot" -Direction Inbound -Protocol TCP -LocalPort 8501 -Action Allow -Profile Domain
   ```
4. Start it from the code folder: `.\.venv\Scripts\streamlit.exe run app.py`. Investigators open
   `https://<machine name>:8501`.

**Run at boot.** Task Scheduler, one task each, "Run whether user is logged on or not", trigger "At
startup", start in the code folder: (1) `velociraptor.exe --config server.config.yaml frontend`, (2) each
image's dead-disk client, (3) `.venv\Scripts\streamlit.exe run app.py`. Run the app as **one** process:
questions, triage and investigations run as jobs inside it (`copilot/jobs.py`). A stopped app loses
nothing: interrupted jobs are offered for **Continue** after the restart.

## 6. Backup and restore

Stop the app (and Velociraptor) or back up while nobody works. Keep these, together:

| What | Why |
|---|---|
| `cases\` (each `case.yaml` and its `data\`: database, chats, reports) | the investigations; holds evidence |
| `auth.yaml` | accounts (password hashes) |
| `server.yaml`, `.streamlit\config.toml`, the TLS files | settings and the model's API key |
| `learned_knowledge.yaml` | lessons approved on this server |
| `server.config.yaml`, `api_client.yaml`, client configs, `*.writeback.yaml` (+ `.bak`), `deaddisk-*.yaml` | Velociraptor identity and the image mappings |
| Velociraptor's datastore (`Datastore.location` in `server.config.yaml`) | its flows and uploads |

Restore: copy them back to the same paths, start Velociraptor, run `python -m copilot.config_check` and
`python -m copilot.selftest`, then start the app and open one case's report tab. A single case also travels
alone: ask the copilot to export the case (`export_case`: the database and CSVs, in **Report & files**),
or copy its `cases\<id>\` folder while the app is stopped.

The backup holds evidence and keys: store it like the evidence.

## 7. Updating

```powershell
git pull
.\.venv\Scripts\pip install -r requirements-lock.txt
python -m pytest tests          # optional
```
Then restart the app task. Stored descriptions are rebuilt by themselves when the normalizer changed.

## Not covered

- Several app processes behind a load balancer: jobs run inside the one app process.
- Containers. A design that fits: one container for the app (Python 3.12, Volatility with symbols built
  in), one for Velociraptor with a helper that adds an image as a client, a TLS proxy in front, evidence
  mounted read-only, secrets and `cases\` in volumes. On Windows this runs in WSL2 (Podman Desktop or
  Docker Engine in WSL are free for company use; Docker Desktop needs a licence in large companies).
  Measure image reads through WSL first: large E01s read over the Windows file share can be much slower
  than natively, and FTK Imager mounts may not reach a container.
