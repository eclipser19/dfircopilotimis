"""The installer (copilot/install.py) without Velociraptor or a network: files, commands, answers."""
import hashlib
import io
import os
import subprocess

import pytest
import yaml

from copilot import auth, config_check, install


def test_each_image_client_gets_its_own_writeback_and_temp_folder():
    template = ("Client:\n  writeback_darwin: /etc/v.yaml\n  writeback_linux: /etc/v.yaml\n"
                "  writeback_windows: $ProgramFiles\\V\\v.yaml\n  tempdir_windows: $ProgramFiles\\V\\Tools\n"
                "  level2_writeback_suffix: .bak\n")
    client = yaml.safe_load(install.client_config_for(template, "C:\\d it's\\wb.yaml", "C:\\d\\tmp"))["Client"]
    assert client["writeback_windows"] == client["writeback_linux"] == "C:\\d it's\\wb.yaml"
    assert client["tempdir_windows"] == "C:\\d\\tmp" and client["level2_writeback_suffix"] == ".bak"


def test_velociraptor_listens_on_localhost_and_keeps_its_datastore(tmp_path):
    merge = install.server_config_merge(install.Layout(str(tmp_path)))
    assert {merge[k]["bind_address"] for k in ("Frontend", "API", "GUI", "Monitoring")} == {"127.0.0.1"}
    assert merge["Datastore"]["location"] == merge["Datastore"]["filestore_directory"]
    assert merge["Datastore"]["location"].startswith(str(tmp_path))


def test_server_settings_are_the_shared_server_defaults(tmp_path):
    data = install.server_settings({"data_dir": str(tmp_path), "base_url": "https://llm/v1", "model": "m",
                                    "api_key": "", "online": True, "port": "8443", "server_name": "dfir01",
                                    "tls_cert": "c.pem", "tls_key": "k.pem"})
    path = tmp_path / "server.yaml"
    install.write_server_yaml(str(path), data)
    assert config_check.check_file(str(path)) == []
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["login"] == {"required": True, "new_evidence": "admins"}
    assert loaded["report"] == {"confirmed_findings_only": True}
    assert loaded["memory"]["offline"] is False and "api_key" not in loaded["llm"]
    assert loaded["deploy"]["port"] == 8443 and loaded["deploy"]["tls_key"] == "k.pem"


def test_the_app_is_on_the_network_only_with_a_certificate():
    local = install.streamlit_command({"port": 8501, "server_name": "dfir01"})
    assert local[local.index("--server.address") + 1] == "127.0.0.1" and "--server.sslCertFile" not in local
    assert install.app_url({"server_name": "dfir01"}) == "http://localhost:8501"
    deploy = {"port": 8443, "tls_cert": "c.pem", "tls_key": "k.pem", "server_name": "dfir01"}
    tls = install.streamlit_command(deploy)
    assert tls[tls.index("--server.address") + 1] == "0.0.0.0"
    assert tls[tls.index("--server.sslKeyFile") + 1] == "k.pem"
    assert install.app_url(deploy) == "https://dfir01:8443"


def test_a_download_with_another_hash_is_not_kept(tmp_path, monkeypatch):
    payload = b"MZ not really velociraptor"
    monkeypatch.setattr(install.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(payload))
    dest = tmp_path / "velociraptor.exe"
    with pytest.raises(install.InstallError, match="not the published"):
        install.download_velociraptor(str(dest), sha256="0" * 64)
    assert not dest.exists() and not (tmp_path / "velociraptor.exe.part").exists()
    install.download_velociraptor(str(dest), sha256=hashlib.sha256(payload).hexdigest())
    assert dest.read_bytes() == payload


def test_each_image_becomes_its_own_client(tmp_path, monkeypatch):
    layout = install.Layout(str(tmp_path / "data"))
    layout.make()
    with open(layout.client_template, "w") as f:
        f.write("Client:\n  writeback_windows: x\n  tempdir_windows: y\n")
    image = tmp_path / "img.E01"
    image.write_bytes(b"EVF")
    calls = []

    def run(cmd, **kwargs):
        assert kwargs["env"]["__COMPAT_LAYER"] == "RunAsInvoker"
        calls.append(cmd)
        with open(cmd[-1], "w") as f:                                   # deaddisk writes the remap file
            f.write("remappings: []\n")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    class Client:                                                        # writes its ID at once, like Velociraptor
        def __init__(self, cmd, cwd, stdout, stderr, env):
            assert env["__COMPAT_LAYER"] == "RunAsInvoker"              # no elevation asked (WinError 740)
            calls.append(cmd)
            with open(os.path.join(cwd, "writeback.yaml"), "w") as f:
                f.write(f"client_id: C.{len(calls):016x}\n")

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(install, "RUN", run)
    monkeypatch.setattr(install, "POPEN", Client)
    info = install.add_image(layout, str(image), "img")
    assert info["client_id"] == "C.0000000000000002" and info["kind"] == "disk"
    assert f"--add_windows_disk={image}" in calls[0] and "--hostname=img" in calls[0]
    config = yaml.safe_load(open(os.path.join(layout.image_dir("img"), "client.config.yaml")))
    assert config["Client"]["writeback_windows"] == os.path.join(layout.image_dir("img"), "writeback.yaml")
    with pytest.raises(install.InstallError, match="already exists"):
        install.add_image(layout, str(image), "img")
    with pytest.raises(install.InstallError, match="Name"):
        install.add_image(layout, str(image), "..\\evil")
    folder = tmp_path / "collected"
    folder.mkdir()
    install.add_image(layout, str(folder), "files")
    assert any(a.startswith("--add_windows_directory=") for a in calls[-2])
    assert {i["name"]: i["client_id"] for i in install.images(layout)} == {"img": "C.0000000000000002",
                                                                           "files": "C.0000000000000004"}


def test_self_signed_certificate_names_the_server(tmp_path):
    from cryptography import x509
    install.self_signed_certificate(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"), "dfir01")
    cert = x509.load_pem_x509_certificate((tmp_path / "c.pem").read_bytes())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert "dfir01" in names and "localhost" in names
    assert b"PRIVATE KEY" in (tmp_path / "k.pem").read_bytes()


def test_setup_asks_only_what_it_cannot_know_and_skips_what_is_done(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_SETTINGS", str(tmp_path / "server.yaml"))
    monkeypatch.setenv("DFIR_AUTH_FILE", str(tmp_path / "auth.yaml"))
    monkeypatch.setenv("DFIR_API_CONFIG", str(tmp_path / "api_client.yaml"))
    downloads = []
    monkeypatch.setattr(install, "download_velociraptor",
                        lambda dest: (downloads.append(dest), open(dest, "wb").write(b"MZ")))

    def run(cmd, **kwargs):
        args = cmd[1:]
        if args == ["version"]:
            return subprocess.CompletedProcess(cmd, 0, f"name: velociraptor\nversion: {install.VELOCIRAPTOR_VERSION}\n", "")
        if "api_client" in args:
            with open(args[-1], "w") as f:
                f.write("api_connection_string: 127.0.0.1:8001\n")
        out = b"Client:\n  writeback_windows: x\n" if args[-1] == "client" else b"Frontend: {}\n"
        return subprocess.CompletedProcess(cmd, 0, out, b"")

    monkeypatch.setattr(install, "RUN", run)
    answers = iter([str(tmp_path / "data"), "n", "https://llm.example/v1", "model-x", "y", "", "dfir01", "", "boss"])
    secrets = iter(["sk-test", "correct horse battery", "correct horse battery"])
    monkeypatch.setattr(install, "INPUT", lambda question: next(answers))
    monkeypatch.setattr(install, "SECRET", lambda question: next(secrets))
    assert install.setup() == 0
    settings = yaml.safe_load((tmp_path / "server.yaml").read_text(encoding="utf-8"))
    assert settings["llm"] == {"base_url": "https://llm.example/v1", "model": "model-x", "api_key": "sk-test"}
    assert "tls_cert" not in settings["deploy"]                         # no certificate: this machine only
    assert auth.is_admin("boss")
    assert (tmp_path / "data" / "velociraptor" / "server.config.yaml").is_file()
    assert (tmp_path / "api_client.yaml").is_file() and len(downloads) == 1

    answers = iter(["", "n"])                                            # again: only the folder and the GUI question
    assert install.setup() == 0 and len(downloads) == 1
