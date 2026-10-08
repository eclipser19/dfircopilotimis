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
