# Deploying DFIR Copilot on a forensic machine

Windows: sections 1-5 below. Linux (SANS SIFT or Ubuntu): [Linux](#linux-sans-sift-or-ubuntu). Both run the same
installer (`python -m copilot.install`): the same questions, layout and checks.

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

## Local only (investigators on the server through Remote Desktop)

When investigators can't reach the server's port (another subnet, a network firewall that lets only RDP
through), they connect with Remote Desktop and use the app in a browser on the server:
`http://localhost:8501`. Leave `tls_cert` / `tls_key` out of `server.yaml`'s `deploy:` section (the app then
listens on 127.0.0.1 only: passwords never cross the network, no certificate or firewall rule is needed),
and remove the rule if it was made: `Remove-NetFirewallRule -DisplayName 'DFIR Copilot'` (admin). Sign-in,
cases, access and each investigator's own chats work the same. Windows Server allows two RDP sessions at a
time without Remote Desktop Services licences. To open it to the network later: ask the network team to
allow the app's port from the investigators' subnet, add a certificate (`python -m copilot.install https
--name <name>`: self-signed, or below), the firewall rule (setup prints it), and restart.

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

## Linux (SANS SIFT or Ubuntu)

For a SIFT Workstation (Ubuntu 22.04, Python 3.10) or Ubuntu 24.04. The copilot gets its own Python
environment and its own account (`dfir`), so SIFT's tools and its own Volatility are untouched, and
analysts keep using the desktop as before. Checked end to end in a container: install, setup, an image
added, everything started, a collection through the copilot, a backup.

| Where | What |
|---|---|
| `/opt/dfir-copilot` | the code (this repository) and its `.venv` |
| `/etc/dfir-copilot` | `server.yaml`, `auth.yaml`, `api_client.yaml`, `env` (the service's settings) |
| `/srv/dfir` | the data folder: Velociraptor (binary, keys, datastore, one folder per image), `cases/`, `logs/`, `memory/`, `symbols/`, `tls/`, `backups/`, `work/` (where the copilot runs: the code folder stays read-only to it) |

**Install**
```bash
sudo git clone https://github.com/eclipser19/bananeabibenmiyaptim /opt/dfir-copilot
sudo /opt/dfir-copilot/deploy/install.sh
```
It installs the Ubuntu packages, makes the `dfir` account and the folders, the Python environment with the
exact tested packages, the `dfir-copilot` service (used by `start.sh --background`) and the nightly backup,
then runs setup, which asks the
questions in the table of section 1 (data folder: `/srv/dfir`) and downloads Velociraptor's Linux build,
checked against its SHA-256. Setup runs as the `dfir` account, not as root, so the service can use what it
makes: at "Data folder" press Enter for `/srv/dfir`, the folder the installer made for it. For another
disk, give the folder to that account first (`sudo install -d -o dfir -g dfir -m 0750 /mnt/big/dfir`), never
a folder inside someone's home such as a Desktop; setup asks again when it cannot write the one given.
Options, as environment variables before the command: `WHEELS=<folder>` and
`VELOCIRAPTOR_BIN=<file>` without internet (below), `INVESTIGATOR_NET=<subnet>` for the firewall.

**Images and accounts**
```bash
sudo dfir-admin install add-image /srv/dfir/evidence/host.E01 --name host   # prints its client ID
sudo dfir-admin install images                                             # every image and its client ID
sudo dfir-admin auth add <investigator>                                    # --admin for admins
```
The `dfir` account must be able to read the image: put it under `/srv/dfir/evidence`, or let the `dfir`
group read where it is (`sudo chgrp -R dfir <folder>; sudo chmod -R g+rX <folder>`), or mount the evidence
share read-only with `gid=dfir`. `dfir-admin` runs any copilot command as that account with the service's
settings (`sudo dfir-admin config_check`, `memory check`, `selftest`, `feedback export`, `benchmark run ...`).

**Run** with `start.sh`, the Linux `start.ps1`:
```bash
sudo /opt/dfir-copilot/start.sh               # Velociraptor, every image's client, the app; Ctrl+C stops all
sudo /opt/dfir-copilot/start.sh --background  # the same, kept running after logout and started at every boot
sudo /opt/dfir-copilot/start.sh --status      # running in the background? its last lines
sudo /opt/dfir-copilot/start.sh --stop        # stops the background one (and its start at boot)
sudo dfir-admin selftest                      # Velociraptor answers and a collection works (needs a case)
```
Without `--background` it stops when its terminal closes: use `--background` on a server nobody stays
logged in to. Each part's log is in `/srv/dfir/logs`. Images added while it runs start within seconds. A
restart loses nothing (interrupted questions are offered for **Continue**).

**From other computers, or the host of this VM.** The app answers on the network only over HTTPS (people
sign in with passwords); without a certificate it answers on this machine alone, at `http://localhost:8501`.
Do not change its address by hand; give it a certificate instead, then start it again:
```bash
sudo dfir-admin install https --name 192.168.56.10    # the name or address people type; self-signed
sudo dfir-admin install https --name dfir01.corp.example --cert <pem> --key <pem>   # a PKI one
```
Then open `https://192.168.56.10:8501` (browsers warn once about a self-signed certificate). `ip -4 addr`
shows this machine's addresses. For the host of a VM: a bridged or host-only network adapter gives the VM
an address the host reaches; VMware's NAT does too; VirtualBox's NAT does not, so add a port forward
(Settings → Network → Port Forwarding: host 8501 → guest 8501) and open `https://localhost:8501` on the
host.

**Investigators in another subnet.** They only use the web page. Ask the network team for one rule:
investigators' subnet → this machine, TCP 8501 (or the port you chose). For a model in the cloud, this
machine also needs HTTPS out to it, directly or through your proxy (`HTTPS_PROXY=` in
`/etc/dfir-copilot/env`). Nothing else crosses: Velociraptor listens on this machine only, and the evidence
stays where it is. This machine's own firewall: run `install.sh` again with
`INVESTIGATOR_NET=10.20.0.0/16` (and `ADMIN_NET=` for SSH, default the same). An investigator checks the way
in from Windows with `Test-NetConnection <this machine> -Port 8501`. Without a certificate the app answers on
this machine only (see "Local only" above).

**Backup** runs every night at 02:30 into `/srv/dfir/backups` (the last 14 kept; another folder:
`sudo /opt/dfir-copilot/deploy/backup.sh /mnt/backup/dfir`). It needs no stop: each case database is copied
safely while the app runs, with the case files, chats and reports, `/etc/dfir-copilot`, Velociraptor's keys,
every image's identity (client IDs stay the same) and the TLS files. Not the evidence, memory images or
Velociraptor's datastore. Restore: stop it, put `cases/` back under `/srv/dfir/cases`, unpack `settings.tar.gz` at
`/`, start it, `sudo dfir-admin selftest`. The backup holds keys and evidence-derived data: store it like the evidence.

**Update**: `sudo /opt/dfir-copilot/deploy/update.sh` (git pull, packages; it restarts a `--background` one,
giving running questions up to ten minutes to finish; one running in a terminal you stop and start again).

**Without internet.** On another Ubuntu machine of the same version (22.04 for SIFT) with internet:
```bash
git clone https://github.com/eclipser19/bananeabibenmiyaptim dfir-copilot && cd dfir-copilot
python3 -m venv /tmp/w && /tmp/w/bin/pip install --upgrade pip && /tmp/w/bin/pip wheel -r requirements-lock.txt -w wheels
curl -LO https://github.com/Velocidex/velociraptor/releases/download/v0.77.2/velociraptor-v0.77.2-linux-amd64
```
Copy the repository folder (with `wheels/`) to `/opt/dfir-copilot` and the binary next to it, then
`sudo WHEELS=/opt/dfir-copilot/wheels VELOCIRAPTOR_BIN=<the binary> /opt/dfir-copilot/deploy/install.sh`
(the binary is refused unless its SHA-256 is the pinned one). Answer "no" to internet in setup and bring
the symbol tables (README, "Symbols and offline use").

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
