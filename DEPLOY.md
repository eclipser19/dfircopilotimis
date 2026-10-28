# Deploying DFIR Copilot on a Windows forensic machine

One Windows machine runs everything; investigators use the web app from their own computers over
HTTPS. The model is reached over the network (any OpenAI-compatible endpoint).

```
Investigators' browsers ──HTTPS :8501──▶ web app (app.py, Python, .venv)
                                            │  gRPC 127.0.0.1:8001 (API, investigator role)
                                            ▼
                                   Velociraptor server (frontend :8000, GUI :8889: this machine only)
                                            ▲
                       one dead-disk client per image (its own identity and remap file)
                                            │ reads
                                   D:\evidence\<image>.E01      Volatility 3 reads <data>\memory\<image>.mem
```

Only the app's port is opened to the network.

## 1. Install

```powershell
git clone <repository> C:\dfir-copilot; cd C:\dfir-copilot
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

`install.ps1` gets Python 3.12 (winget, for this user, if missing), `.venv`, the exact tested packages,
then runs `python -m copilot.install setup`, which asks:

| Question | Answer |
|---|---|
| Data folder | Where Velociraptor, its datastore, logs, memory images and symbols go (default `C:\dfir`; a disk with room) |
| Velociraptor GUI account | Optional; the copilot doesn't need it |
| Model endpoint, name, API key | Your OpenAI-compatible endpoint; an empty key = each investigator enters their own |
| Internet | Yes: Volatility downloads symbol tables itself |
| Port, name investigators use | e.g. 8501 and `dfir01.corp.example` |
| Certificate | A PEM certificate and key for that name from your company PKI; `self` = a self-signed one (browsers warn once); empty = the app answers on this machine only |
| Admin account | Name and password (12+ characters) |

It downloads Velociraptor 0.77.2 (checked against its published SHA-256) and writes its server config
with every port on 127.0.0.1 and the datastore in the data folder (not in `C:\Windows\Temp`, which
Windows cleans), the API config with the `investigator` role (it can collect, not run commands on the
server), and `server.yaml` with the shared-server defaults: sign-in required, new evidence opened by
admins (`login.new_evidence`), reports with confirmed findings only (`report.confirmed_findings_only`).
Running it again keeps everything that exists.

At the end it prints two commands for an **admin** PowerShell, to run once:
- a firewall rule for the app's port (domain and private networks);
- a scheduled task that runs `python -m copilot.install start` at boot as SYSTEM, restarted if it stops.

## 2. Images and accounts

```powershell
.\.venv\Scripts\python.exe -m copilot.install add-image D:\evidence\host.E01 --name host
.\.venv\Scripts\python.exe -m copilot.install images          # every image and its client ID
.\.venv\Scripts\python.exe -m copilot.auth add <investigator>  # more accounts; --admin for admins
```

- Each image gets its own client (writeback = identity): two images sharing one would share a client ID,
  and the copilot would treat them as the same evidence.
- E01: the first segment, the others in the same folder. A folder works too (`--add_windows_directory`):
  an AD1 mounted or exported with FTK Imager, or collected files, holding `Windows` and `Users`.
- Keep evidence read-only (file attribute or a read-only share): the copilot never writes to it.
- An admin creates the first case on each image (**New case**, the client ID) and adds the investigators
  under **Case → Access**.

## 3. Run

`.\start.ps1` (or the scheduled task) starts Velociraptor, every image's client and the app, and stops
them all with Ctrl+C. Logs: `<data folder>\logs\`. Images added while it runs start within seconds.
Questions and investigations run as jobs inside the app process: run **one** app. A restart loses
nothing; interrupted jobs are offered for **Continue**.

Checks: `python -m copilot.selftest` (Velociraptor answers, a collection works), `python -m copilot.memory
check`, `python -m copilot.config_check`.

## 4. Backup and restore

Stop the app (the task, or Ctrl+C), then copy together:

| What | Where |
|---|---|
| The data folder: Velociraptor (CA key, datastore, every image's identity and remap), TLS files, memory images, symbols | `C:\dfir\` (or the one you chose) |
| `server.yaml`, `auth.yaml`, `api_client.yaml`, `learned_knowledge.yaml` | the code folder |
| `cases\` (case files; databases, chats, reports in each `data\`) | the code folder |

Restore: the same paths, then `python -m copilot.config_check`, `.\start.ps1`, `python -m copilot.selftest`,
and open a case. A single case also travels alone: its `cases\<id>\` folder (app stopped), or ask the
copilot to export it (`export_case`: the database and CSVs, in **Report & files**).
The backup holds evidence and keys: store it like the evidence.

## 5. Updating

```powershell
git pull
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pytest tests        # optional, about 3 minutes
```
Then restart the task. Stored descriptions are rebuilt by themselves when the normalizer changed.

## A certificate from the PKI later

Put the PEM files somewhere outside the code folder and set them in `server.yaml`:
```yaml
deploy:
  tls_cert: 'C:\dfir\tls\pki-cert.pem'
  tls_key: 'C:\dfir\tls\pki-key.pem'
  server_name: dfir01.corp.example
```
Restart. Without `tls_cert`/`tls_key` the app listens on 127.0.0.1 only: passwords never cross the
network in clear text.

## By hand

What the installer does, for another system or to see the pieces (README "Setup" explains each):
`velociraptor config generate --merge_file` with the bind addresses and datastore above; `config api_client
--role investigator`; `config client`, copied per image with its own `writeback_*` and `tempdir_*`;
`velociraptor deaddisk --add_windows_disk=<image> --hostname=<name> <remap.yaml>`; then
`velociraptor --config <client config> --remap <remap.yaml> client`, the frontend, and
`streamlit run app.py --server.address 0.0.0.0 --server.sslCertFile … --server.sslKeyFile …`.

## Not covered

- Several app processes behind a load balancer: jobs run inside the one app process.
- Containers. A design that fits: one container for the app (Python 3.12, Volatility with symbols built
  in), one for Velociraptor with `add-image`, a TLS proxy in front, evidence mounted read-only, secrets and
  `cases\` in volumes. On Windows this runs in WSL2 (Podman Desktop or Docker Engine in WSL are free for
  company use; Docker Desktop needs a licence in large companies). Measure image reads through WSL first:
  large E01s read over the Windows file share can be much slower than natively, and FTK Imager mounts may
  not reach a container.
