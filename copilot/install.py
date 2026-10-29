"""
Installs the copilot on a fresh Windows or Linux machine (SANS SIFT, Ubuntu), asking only what it can't
know. `install.ps1` (Windows) and `deploy/install.sh` (Linux) run `setup` after they have installed Python
and the packages.

  python -m copilot.install setup                         Velociraptor (downloaded, server, API), server.yaml,
                                                          HTTPS certificate, first admin account
  python -m copilot.install add-image <path> [--name N]   a disk image (E01 / raw) or a folder of collected files
                                                          as its own dead-disk client; prints its client ID
  python -m copilot.install images                        the images added, with their client IDs
  python -m copilot.install start                         Velociraptor, every image's client and the web app
                                                          (images added later start by themselves); Ctrl+C stops all

What it makes goes into the data folder (server.yaml `deploy.data_dir`, default C:\\dfir or /srv/dfir), except the
files the copilot reads from the code folder (or where DFIR_SETTINGS, DFIR_AUTH_FILE, DFIR_API_CONFIG point):
server.yaml, auth.yaml, api_client.yaml. Every step is skipped
when its file exists, so running setup again only fills in what is missing.
"""
import argparse
import datetime
import getpass
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

import yaml

VELOCIRAPTOR_VERSION = "0.77.2"                 # the version the copilot was tested with
_RELEASE = ("https://github.com/Velocidex/velociraptor/releases/download/"
            f"v{VELOCIRAPTOR_VERSION}/velociraptor-v{VELOCIRAPTOR_VERSION}-")
# The release file for each system and its SHA-256. Windows: GitHub's digest. Linux: the release file's
# (two downloads, 2026-10-21 and 2026-10-29, agree; GitHub's API was not reachable to cross-check it).
VELOCIRAPTOR_BUILDS = {
    "windows": (_RELEASE + "windows-amd64.exe", "686e4f5888fdd66d07ace3b6c1cbd7d2dd0d8d5fb4d3b5d905a7df3341dfb86f"),
    "linux": (_RELEASE + "linux-amd64", "6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077"),
}
SYSTEM = "windows" if os.name == "nt" else "linux"
VELOCIRAPTOR_URL, VELOCIRAPTOR_SHA256 = VELOCIRAPTOR_BUILDS[SYSTEM]
DEFAULT_DATA_DIR = r"C:\dfir" if SYSTEM == "windows" else "/srv/dfir"
DEFAULT_PORT = 8501
API_PORT = 8001
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Swapped by the tests.
INPUT = input
SECRET = getpass.getpass
RUN = subprocess.run
POPEN = subprocess.Popen


class InstallError(Exception):
    pass


# ---------------------------------------------------------------- questions
def ask(question: str, default: str = "") -> str:
    answer = INPUT(f"{question}{f' [{default}]' if default else ''}: ").strip()
    return answer or default


def ask_yes(question: str, default: bool = True) -> bool:
    answer = INPUT(f"{question} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer in ("y", "yes")


def step(text: str):
    print(f"\n== {text}")


# ---------------------------------------------------------------- where things go
class Layout:
    """The data folder: Velociraptor (binary, configs, datastore, one folder per image), logs, memory
    images, symbols, YARA rules, TLS files."""

    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        self.vr_dir = os.path.join(self.data_dir, "velociraptor")
        self.exe = os.path.join(self.vr_dir, "velociraptor.exe" if SYSTEM == "windows" else "velociraptor")
        self.server_config = os.path.join(self.vr_dir, "server.config.yaml")
        self.client_template = os.path.join(self.vr_dir, "client.config.yaml")
        self.datastore = os.path.join(self.vr_dir, "datastore")
        self.images = os.path.join(self.vr_dir, "images")
        self.logs = os.path.join(self.data_dir, "logs")
        self.memory = os.path.join(self.data_dir, "memory")
        self.symbols = os.path.join(self.data_dir, "symbols")
        self.yara = os.path.join(self.data_dir, "yara")
        self.tls = os.path.join(self.data_dir, "tls")

    def make(self):
        for path in (self.vr_dir, self.datastore, self.images, self.logs, self.memory, self.symbols,
                     self.yara, self.tls):
            os.makedirs(path, exist_ok=True)

    def image_dir(self, name: str) -> str:
        return os.path.join(self.images, name)


def code_path(name: str) -> str:
    return os.path.join(CODE_DIR, name)


def settings_path() -> str:
    path = os.environ.get("DFIR_SETTINGS", "server.yaml")
    return path if os.path.isabs(path) else code_path(path)


def api_config_path() -> str:
    path = os.environ.get("DFIR_API_CONFIG", "api_client.yaml")
    return path if os.path.isabs(path) else code_path(path)


def deploy_settings() -> dict:
    """server.yaml's deploy section ({} without one)."""
    try:
        with open(settings_path(), encoding="utf-8") as f:
            return dict((yaml.safe_load(f) or {}).get("deploy") or {})
    except (OSError, yaml.YAMLError, AttributeError):
        return {}


def layout_from_settings() -> Layout:
    return Layout(deploy_settings().get("data_dir") or DEFAULT_DATA_DIR)


# ---------------------------------------------------------------- Velociraptor
def download_velociraptor(dest: str, url: str = VELOCIRAPTOR_URL, sha256: str = VELOCIRAPTOR_SHA256):
    """Downloads the pinned release and keeps it only if its SHA-256 is the published one."""
    part = dest + ".part"
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=120) as response, open(part, "wb") as out:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != sha256:
        os.remove(part)
        raise InstallError(f"The download's SHA-256 is {digest.hexdigest()}, not the published {sha256}: not used.")
    if SYSTEM != "windows":
        os.chmod(part, 0o755)
    os.replace(part, dest)


def vr_env() -> dict:
    """Velociraptor's binary asks Windows for the highest rights available: for an administrator's
    non-elevated window, starting it then fails (WinError 740). It needs no admin rights to read an image
    or serve the copilot, so it runs with the caller's own (RunAsInvoker), like any program."""
    return dict(os.environ, __COMPAT_LAYER="RunAsInvoker")


def velociraptor_version(exe: str) -> str:
    out = RUN([exe, "version"], capture_output=True, text=True, timeout=60, env=vr_env())
    found = re.search(r"^version:\s*(\S+)", out.stdout or "", re.M)
    return found.group(1) if found else ""


def server_config_merge(layout: Layout) -> dict:
    """What we change in Velociraptor's generated config: every port on 127.0.0.1 (only this machine's
    copilot and dead-disk clients talk to it) and the datastore in the data folder, not in a temp folder."""
    local = {"bind_address": "127.0.0.1"}
    return {"Frontend": dict(local), "API": dict(local), "GUI": dict(local), "Monitoring": dict(local),
            "Datastore": {"location": layout.datastore, "filestore_directory": layout.datastore}}


def _velociraptor(layout: Layout, *args, capture: bool = True, timeout: int = 300):
    out = RUN([layout.exe, *args], cwd=layout.vr_dir, capture_output=capture, timeout=timeout, env=vr_env())
    if out.returncode != 0:
        detail = (out.stderr or b"").decode("utf-8", "replace").strip().splitlines()[-3:] if capture else []
        raise InstallError(f"velociraptor {' '.join(args[:3])} failed: {' / '.join(detail) or out.returncode}")
    return out


def make_server_config(layout: Layout):
    merge = os.path.join(layout.vr_dir, "merge.json")
    with open(merge, "w", encoding="utf-8") as f:
        json.dump(server_config_merge(layout), f)
    try:
        out = _velociraptor(layout, "config", "generate", "--merge_file", merge)
    finally:
        os.remove(merge)
    with open(layout.server_config, "wb") as f:
        f.write(out.stdout)


def make_api_client(layout: Layout, dest: str):
    # investigator: may collect, may not run commands on the server or write files (the real safety net).
    _velociraptor(layout, "--config", layout.server_config, "config", "api_client", "--name", "dfir_copilot",
                  "--role", "investigator", dest)


def make_client_template(layout: Layout):
    out = _velociraptor(layout, "--config", layout.server_config, "config", "client")
    with open(layout.client_template, "wb") as f:
        f.write(out.stdout)


def _yaml_quote(path: str) -> str:
    return "'" + path.replace("'", "''") + "'"


def client_config_for(template: str, writeback: str, tempdir: str) -> str:
    """The client config of one image: its own writeback (the writeback is the client's identity: two
    images sharing one would share a client ID) and a temp folder it can write to."""
    text = re.sub(r"(?m)^(\s*writeback_(?:windows|linux|darwin):).*$",
                  lambda m: f"{m.group(1)} {_yaml_quote(writeback)}", template)
    return re.sub(r"(?m)^(\s*tempdir_(?:windows|linux|darwin):).*$",
                  lambda m: f"{m.group(1)} {_yaml_quote(tempdir)}", text)


def _client_id(writeback: str) -> str:
    try:
        with open(writeback, encoding="utf-8") as f:
            return str((yaml.safe_load(f) or {}).get("client_id") or "")
    except (OSError, yaml.YAMLError, AttributeError):
        return ""


def add_image(layout: Layout, path: str, name: str) -> dict:
    """One disk image (or a folder holding Windows and Users) as its own dead-disk client."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise InstallError(f"No file or folder {path}.")
    if not NAME_RE.match(name or ""):
        raise InstallError("Name: letters, digits, '-' and '_' (up to 63), starting with a letter or digit.")
    folder = layout.image_dir(name)
    if os.path.exists(folder):
        raise InstallError(f"An image named '{name}' already exists ({folder}).")
    if not os.path.isfile(layout.client_template):
        raise InstallError("Run `python -m copilot.install setup` first (no Velociraptor client config yet).")
    os.makedirs(os.path.join(folder, "tmp"))
    kind = "directory" if os.path.isdir(path) else "disk"
    _velociraptor(layout, "deaddisk", f"--add_windows_{kind}={path}", f"--hostname={name}",
                  os.path.join(folder, "remap.yaml"))
    with open(layout.client_template, encoding="utf-8") as f:
        template = f.read()
    writeback = os.path.join(folder, "writeback.yaml")
    with open(os.path.join(folder, "client.config.yaml"), "w", encoding="utf-8") as f:
        f.write(client_config_for(template, writeback, os.path.join(folder, "tmp")))
    # The client writes its ID into the writeback as soon as it starts, server running or not.
    with open(os.path.join(folder, "first_start.log"), "wb") as log:
        proc = _start_client(layout, folder, log)
        try:
            for _ in range(60):
                if _client_id(writeback):
                    break
                time.sleep(0.5)
        finally:
            proc.terminate()
            proc.wait(timeout=30)
    info = {"name": name, "path": path, "kind": kind, "client_id": _client_id(writeback),
            "added": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    with open(os.path.join(folder, "image.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(info, f, sort_keys=False)
    return info


def images(layout: Layout) -> list:
    """The images added, oldest first ({name, path, client_id, ...})."""
    found = []
    if os.path.isdir(layout.images):
        for name in sorted(os.listdir(layout.images)):
            folder = layout.image_dir(name)
            if not os.path.isfile(os.path.join(folder, "remap.yaml")):
                continue
            try:
                with open(os.path.join(folder, "image.yaml"), encoding="utf-8") as f:
                    info = yaml.safe_load(f) or {}
            except (OSError, yaml.YAMLError):
                info = {"name": name}
            info["client_id"] = info.get("client_id") or _client_id(os.path.join(folder, "writeback.yaml"))
            found.append(info)
    return sorted(found, key=lambda i: str(i.get("added") or ""))


def _start_client(layout: Layout, folder: str, log):
    return POPEN([layout.exe, "--config", os.path.join(folder, "client.config.yaml"),
                  "--remap", os.path.join(folder, "remap.yaml"), "client"],
                 cwd=folder, stdout=log, stderr=subprocess.STDOUT, env=vr_env())


# ---------------------------------------------------------------- server.yaml, HTTPS, accounts
def server_settings(answers: dict) -> dict:
    """server.yaml for a shared server: sign-in required, new evidence opened by admins, reports with
    confirmed findings only."""
    layout = Layout(answers["data_dir"])
    llm = {"base_url": answers.get("base_url", ""), "model": answers.get("model", "")}
    if answers.get("api_key"):
        llm["api_key"] = answers["api_key"]
    deploy = {"data_dir": layout.data_dir, "port": int(answers.get("port") or DEFAULT_PORT)}
    for key in ("server_name", "tls_cert", "tls_key"):
        if answers.get(key):
            deploy[key] = answers[key]
    return {
        "llm": llm,
        "login": {"required": True, "new_evidence": "admins"},
        "memory": {"images_dir": layout.memory, "symbols_dir": layout.symbols, "yara_dir": layout.yara,
                   "offline": not answers.get("online", True)},
        "report": {"confirmed_findings_only": True},
        "deploy": deploy,
    }


def write_server_yaml(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Written by `python -m copilot.install setup`. Every option is explained in server.example.yaml.\n"
                "# Never commit this file (it can hold the model's API key).\n")
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def self_signed_certificate(cert_path: str, key_path: str, name: str, days: int = 825):
    """A self-signed certificate for `name` (browsers warn once per computer; a company PKI one doesn't)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    alt = [x509.DNSName(n) for n in dict.fromkeys([name, socket.gethostname(), "localhost"]) if n]
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .sign(key, hashes.SHA256()))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _tls_answers(layout: Layout, server_name: str) -> dict:
    print("Investigators sign in with a password, so the app is served to other computers over HTTPS only.\n"
          "Without a certificate it listens on this machine alone (https is then not needed).")
    while True:
        cert = ask("Certificate file (PEM) from your company PKI; 'self' = make a self-signed one; empty = this machine only")
        if not cert:
            return {}
        if cert.lower() == "self":
            cert_path, key_path = os.path.join(layout.tls, "cert.pem"), os.path.join(layout.tls, "key.pem")
            self_signed_certificate(cert_path, key_path, server_name)
            print(f"Made {cert_path} for {server_name} (browsers will warn once; replace it with a PKI one later).")
            return {"tls_cert": cert_path, "tls_key": key_path}
        key = ask("Its private key file (PEM)")
        if os.path.isfile(cert) and os.path.isfile(key):
            return {"tls_cert": os.path.abspath(cert), "tls_key": os.path.abspath(key)}
        print("One of these files doesn't exist; try again.")


def _create_admin():
    from copilot import auth
    while True:
        name = ask("Admin account name", getpass.getuser().lower())
        password = SECRET("Password (12+ characters): ")
        if password != SECRET("Same password again: "):
            print("The passwords differ; try again.")
            continue
        try:
            auth.add_user(name, password, admin=True)
        except ValueError as e:
            print(e)
            continue
        print(f"Admin '{name}' created. Add investigators with `python -m copilot.auth add <name>`.")
        return name


# ---------------------------------------------------------------- the web app
def streamlit_command(deploy: dict) -> list:
    """The app on every network address only with a certificate; without one, on this machine only."""
    tls = bool(deploy.get("tls_cert") and deploy.get("tls_key"))
    cmd = [sys.executable, "-m", "streamlit", "run", code_path("app.py"),
           "--server.headless", "true", "--browser.gatherUsageStats", "false",
           "--server.port", str(deploy.get("port") or DEFAULT_PORT),
           "--server.address", "0.0.0.0" if tls else "127.0.0.1"]
    if tls:
        cmd += ["--server.sslCertFile", deploy["tls_cert"], "--server.sslKeyFile", deploy["tls_key"]]
        if deploy.get("server_name"):
            cmd += ["--browser.serverAddress", str(deploy["server_name"])]
    return cmd


def app_url(deploy: dict) -> str:
    tls = bool(deploy.get("tls_cert") and deploy.get("tls_key"))
    host = (deploy.get("server_name") or socket.gethostname()) if tls else "localhost"
    return f"{'https' if tls else 'http'}://{host}:{deploy.get('port') or DEFAULT_PORT}"


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def start(layout: Layout, deploy: dict, wait_api: int = 90):
    """Velociraptor's frontend, then every image's client, then the app; new images start as they are
    added. Stops everything when one of the three stops (a scheduled task then restarts it all)."""
    if not os.path.isfile(layout.server_config):
        raise InstallError("Run `python -m copilot.install setup` first (no Velociraptor server config).")
    os.chdir(CODE_DIR)                                    # the copilot finds server.yaml, auth.yaml... here
    os.makedirs(layout.logs, exist_ok=True)
    procs = {}

    def launch(label, cmd, cwd):
        log = open(os.path.join(layout.logs, f"{label}.log"), "ab")
        procs[label] = POPEN(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, env=vr_env())
        print(f"started {label} (log: {log.name})")

    try:
        if _port_open(API_PORT):
            print(f"Port {API_PORT} is already in use: is Velociraptor already running? Stop it first.")
            return 1
        launch("velociraptor", [layout.exe, "--config", layout.server_config, "frontend"], layout.vr_dir)
        for _ in range(wait_api):
            if _port_open(API_PORT):
                break
            if procs["velociraptor"].poll() is not None:
                raise InstallError(f"Velociraptor stopped at once: see {os.path.join(layout.logs, 'velociraptor.log')}")
            time.sleep(1)
        launch("app", streamlit_command(deploy), CODE_DIR)
        print(f"\nThe copilot: {app_url(deploy)}   (Ctrl+C stops everything)")
        while True:
            for info in images(layout):
                label = f"image-{info['name']}"
                if label not in procs:
                    folder = layout.image_dir(info["name"])
                    log = open(os.path.join(layout.logs, f"{label}.log"), "ab")
                    procs[label] = _start_client(layout, folder, log)
                    print(f"started {label} (client {info.get('client_id') or '?'})")
            for label in ("velociraptor", "app"):
                if procs[label].poll() is not None:
                    print(f"{label} stopped (exit {procs[label].returncode}): see "
                          f"{os.path.join(layout.logs, label + '.log')}")
                    return 1
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping.")
        return 0
    finally:
        for proc in procs.values():
            if proc.poll() is None:
                proc.terminate()


# ---------------------------------------------------------------- setup
def data_folder(existing: dict) -> Layout:
    """The data folder, asked until it is one the account running setup can write (on Linux that account is
    the service's, dfir, not root: deploy/install.sh runs setup as it)."""
    while True:
        layout = Layout(ask("Data folder (Velociraptor, logs, memory images, symbols)",
                            existing.get("data_dir") or DEFAULT_DATA_DIR))
        try:
            layout.make()
            return layout
        except PermissionError:
            user = getpass.getuser()
            print(f"[!] Setup runs as the account '{user}', which cannot write {layout.data_dir}.")
            if SYSTEM == "windows":
                print("    Pick a folder this account can write, e.g. on a data disk.")
            else:
                print(f"    Press Enter for {DEFAULT_DATA_DIR} (made for it by deploy/install.sh), or give it the folder first:\n"
                      f"      sudo install -d -o {user} -g {user} -m 0750 {layout.data_dir}\n"
                      f"    (not a folder in someone's home, such as a Desktop: the service cannot use those).")


def setup() -> int:
    print("DFIR Copilot setup. Press Enter to take the value in [brackets].")
    existing = deploy_settings()
    layout = data_folder(existing)

    step(f"Velociraptor {VELOCIRAPTOR_VERSION}")
    if not os.path.isfile(layout.exe):
        print(f"Downloading {VELOCIRAPTOR_URL}")
        download_velociraptor(layout.exe)
        print("SHA-256 matches the published one.")
    version = velociraptor_version(layout.exe)
    print(f"{layout.exe}: version {version or '?'}")
    if version != VELOCIRAPTOR_VERSION:
        print(f"[!] The copilot was tested with {VELOCIRAPTOR_VERSION}.")
    if not os.path.isfile(layout.server_config):
        make_server_config(layout)
        print(f"Made {layout.server_config} (all ports on 127.0.0.1, datastore in {layout.datastore}).")
    else:
        print(f"Kept {layout.server_config}.")
    api = api_config_path()
    if not os.path.isfile(api):
        make_api_client(layout, api)
        print(f"Made {api} (role investigator).")
    else:
        print(f"Kept {api}.")
    if not os.path.isfile(layout.client_template):
        make_client_template(layout)
    if ask_yes("Create an account for Velociraptor's own web GUI (https://127.0.0.1:8889, optional)?", False):
        name = ask("GUI account name", "admin")
        RUN([layout.exe, "--config", layout.server_config, "user", "add", name, "--role", "administrator"],
            cwd=layout.vr_dir, env=vr_env())

    step("Server settings (server.yaml)")
    path = settings_path()
    if os.path.isfile(path):
        print(f"Kept {path}. (Delete it and run setup again to answer these questions anew.)")
        if not existing.get("data_dir"):
            print(f"[!] It has no deploy section: add `deploy: {{data_dir: '{layout.data_dir}'}}` (and port, "
                  f"server_name, tls_cert, tls_key for HTTPS) so `start` finds the data folder.")
    else:
        example = {}
        try:
            with open(code_path("server.example.yaml"), encoding="utf-8") as f:
                example = (yaml.safe_load(f) or {}).get("llm") or {}
        except (OSError, yaml.YAMLError):
            pass
        answers = {"data_dir": layout.data_dir}
        print("The model: any OpenAI-compatible endpoint (a local one too, see README 'Offline / local model').")
        answers["base_url"] = ask("Model endpoint (base URL)", example.get("base_url", ""))
        answers["model"] = ask("Model name", example.get("model", ""))
        answers["api_key"] = SECRET("API key (input hidden; empty = each investigator enters their own): ").strip()
        answers["online"] = ask_yes("Does this machine have internet? (Volatility then downloads symbol tables itself)")
        answers["port"] = ask("Port of the web app", str(DEFAULT_PORT))
        answers["server_name"] = ask("Name investigators use to reach this machine", socket.getfqdn())
        answers.update(_tls_answers(layout, answers["server_name"]))
        write_server_yaml(path, server_settings(answers))
        print(f"Wrote {path}.")

    step("Accounts")
    from copilot import auth
    if auth.configured():
        print(f"Kept {auth.auth_file()} ({', '.join(auth.usernames())}).")
    else:
        _create_admin()

    step("Check")
    from copilot import config_check
    config_check.main([path])
    deploy = deploy_settings()
    tls = bool(deploy.get("tls_cert") and deploy.get("tls_key"))
    python = sys.executable
    if SYSTEM != "windows":
        print(_linux_next_steps(deploy, tls))
        return 0
    print(f"""
Done. Next:
  1. Add each disk image (E01: the first segment; the others in the same folder):
       {python} -m copilot.install add-image D:\\evidence\\<image>.E01 --name <short-name>
  2. Start everything (Ctrl+C stops it):
       {python} -m copilot.install start
     then open {app_url(deploy)}, sign in, New case, and give it the image's client ID.
  3. Check Velociraptor once it runs: {python} -m copilot.selftest""")
    if tls:
        print(f"""  4. In an admin PowerShell, once: open the port to the network, and start everything at boot:
       New-NetFirewallRule -DisplayName 'DFIR Copilot' -Direction Inbound -Protocol TCP -LocalPort {deploy.get('port') or DEFAULT_PORT} -Action Allow -Profile Domain,Private
       $a = New-ScheduledTaskAction -Execute '{python}' -Argument '-m copilot.install start' -WorkingDirectory '{CODE_DIR}'
       $s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
       Register-ScheduledTask -TaskName 'DFIR Copilot' -Action $a -Settings $s -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest""")
    else:
        print("  (No certificate: the app is reachable from this machine only. Run setup again after deleting "
              "server.yaml, or add deploy.tls_cert / tls_key to it, to open it to investigators.)")
    print("Backups and updates: DEPLOY.md.")
    return 0


def _linux_next_steps(deploy: dict, tls: bool) -> str:
    """What to do after setup on Linux, where deploy/install.sh made the dfir-copilot service and dfir-admin."""
    port = deploy.get("port") or DEFAULT_PORT
    network = (f"  5. Investigators in another subnet: the network team allows TCP {port} from their subnet to this\n"
               f"     machine. This machine's own firewall: deploy/install.sh with INVESTIGATOR_NET=<their subnet>."
               if tls else
               "  (No certificate: the app answers on this machine only. Delete server.yaml and run setup again,\n"
               "   or add deploy.tls_cert / tls_key to it, to open it to investigators.)")
    return f"""
Done. Next:
  1. Add each disk image (E01: the first segment, the others in the same folder; the dfir group must read it):
       sudo dfir-admin install add-image /srv/dfir/evidence/<image>.E01 --name <short-name>
  2. Start everything now and at every boot (Velociraptor, every image's client, the app):
       sudo systemctl enable --now dfir-copilot          logs: journalctl -u dfir-copilot, {deploy.get('data_dir', DEFAULT_DATA_DIR)}/logs
     then open {app_url(deploy)}, sign in, New case, and give it the image's client ID.
  3. Check Velociraptor once it runs: sudo dfir-admin selftest
  4. More accounts: sudo dfir-admin auth add <name>   (--admin for admins)
{network}
Backups and updates: DEPLOY.md (Linux)."""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m copilot.install", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup", help="install Velociraptor, settings, HTTPS and the first admin")
    add = sub.add_parser("add-image", help="a disk image or folder as its own dead-disk client")
    add.add_argument("path")
    add.add_argument("--name", help="short name (default: from the file name)")
    sub.add_parser("images", help="the images added and their client IDs")
    sub.add_parser("start", help="Velociraptor, the images' clients and the web app")
    args = parser.parse_args(argv)
    os.chdir(CODE_DIR)
    try:
        if args.command == "setup":
            return setup()
        layout = layout_from_settings()
        if args.command == "add-image":
            name = args.name or re.sub(r"[^A-Za-z0-9_-]+", "-", os.path.splitext(os.path.basename(
                args.path.rstrip("\\/")))[0]).strip("-_")[:63]
            info = add_image(layout, args.path, name)
            print(f"Added '{info['name']}' ({info['path']}).\nClient ID: {info['client_id'] or '? (see `images` after start)'}"
                  f"\nA running `start` picks it up within seconds; in the app: New case, client ID {info['client_id']}.")
            return 0
        if args.command == "images":
            rows = images(layout)
            for info in rows:
                print(f"{info.get('name')}\t{info.get('client_id') or '?'}\t{info.get('path', '')}")
            if not rows:
                print("No images yet: python -m copilot.install add-image <path> --name <short-name>")
            return 0
        return start(layout, deploy_settings())
    except InstallError as e:
        print(f"[!] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
