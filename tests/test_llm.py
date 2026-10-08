import pytest

from copilot import llm


@pytest.mark.parametrize("url, local", [
    ("http://localhost:11434/v1", True),
    ("http://127.0.0.1:8000/v1", True),
    ("http://10.0.5.20:8000/v1", True),
    ("http://192.168.1.50/v1", True),
    ("http://gpu-box.local:8080/v1", True),
    ("https://tag-news-resource.services.ai.azure.com/openai/v1", False),
    ("https://api.openai.com/v1", False),
    ("http://8.8.8.8/v1", False),
])
def test_local_endpoints_are_recognised(monkeypatch, url, local):
    monkeypatch.setenv("DFIR_LLM_BASE_URL", url)
    assert llm.is_local() is local


def test_local_flag_for_internal_hostnames(monkeypatch):
    monkeypatch.setenv("DFIR_LLM_BASE_URL", "http://llm.corp.example/v1")
    assert not llm.is_local()
    monkeypatch.setenv("DFIR_LLM_LOCAL", "1")
    assert llm.is_local()


def test_who_needs_a_key(monkeypatch):
    assert llm.needs_user_key()                                   # cloud, no server key
    monkeypatch.setenv("DFIR_LLM_API_KEY", "sk-server")
    assert not llm.needs_user_key() and llm.server_key() == "sk-server"
    monkeypatch.delenv("DFIR_LLM_API_KEY")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-legacy")
    assert llm.server_key() == "sk-legacy"
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.setenv("DFIR_LLM_BASE_URL", "http://localhost:11434/v1")
    assert not llm.needs_user_key()


def test_local_model_needs_no_key(monkeypatch):
    monkeypatch.setenv("DFIR_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("DFIR_LLM_MODEL", "qwen3:32b")
    monkeypatch.setenv("DFIR_LLM_TIMEOUT", "900")
    model = llm.make_llm()
    assert model.model_name == "qwen3:32b"
    assert model.openai_api_base == "http://localhost:11434/v1"
    assert model.openai_api_key.get_secret_value() == llm.NO_KEY
    assert model.request_timeout == 900


def test_user_key_wins_and_defaults_are_kept(monkeypatch):
    model = llm.make_llm("sk-user")
    assert model.openai_api_key.get_secret_value() == "sk-user"
    assert model.model_name == llm.DEFAULT_MODEL and model.openai_api_base == llm.DEFAULT_BASE_URL


def _write_settings(path, text):
    import os
    import time
    path.write_text(text, encoding="utf-8")
    os.utime(path, (time.time() + 1, time.time() + 1))     # a new mtime even within the same second


def test_model_settings_come_from_server_yaml(tmp_path, monkeypatch):
    settings_file = tmp_path / "server.yaml"
    monkeypatch.setenv("DFIR_SETTINGS", str(settings_file))
    _write_settings(settings_file, "llm:\n  base_url: http://10.1.2.3:8000/v1\n  model: local-model\n  timeout: 600\n")
    assert llm.base_url() == "http://10.1.2.3:8000/v1" and llm.model_name() == "local-model"
    assert llm.is_local() and not llm.needs_user_key()
    assert llm.make_llm().request_timeout == 600
    monkeypatch.setenv("DFIR_LLM_MODEL", "from-env")                 # the environment wins
    assert llm.model_name() == "from-env"


def test_server_yaml_key_and_edits_are_picked_up(tmp_path, monkeypatch):
    settings_file = tmp_path / "server.yaml"
    monkeypatch.setenv("DFIR_SETTINGS", str(settings_file))
    assert llm.needs_user_key()                                         # no file yet
    _write_settings(settings_file, "llm:\n  api_key: sk-from-file\n")
    assert llm.server_key() == "sk-from-file" and not llm.needs_user_key()
    _write_settings(settings_file, "llm:\n  local: true\n  base_url: https://gpu.corp.example/v1\n")
    assert llm.is_local() and llm.server_key() == ""


def test_login_can_be_required_from_server_yaml(tmp_path, monkeypatch):
    from copilot import auth
    settings_file = tmp_path / "server.yaml"
    monkeypatch.setenv("DFIR_SETTINGS", str(settings_file))
    assert not auth.login_required()
    _write_settings(settings_file, "login:\n  required: true\n")
    assert auth.login_required()
