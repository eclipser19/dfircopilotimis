"""
The chat model. Any OpenAI-compatible endpoint works: Azure OpenAI / OpenAI, or a local
server (Ollama, vLLM, LM Studio, llama.cpp server) for fully offline use.

Set in server.yaml under `llm:` (see copilot/settings.py), or with environment variables:
    base_url  / DFIR_LLM_BASE_URL   endpoint, e.g. http://localhost:11434/v1 for Ollama
    model     / DFIR_LLM_MODEL      model name on that endpoint (it must support tool calling)
    api_key   / DFIR_LLM_API_KEY    key (OPENAI_API_KEY also works); local endpoints need none
    local     / DFIR_LLM_LOCAL      treat the endpoint as local even if it isn't on a private address
    timeout   / DFIR_LLM_TIMEOUT    seconds per call (default 300; local models can be slow)
"""
import ipaddress
import os
from urllib.parse import urlparse

from langchain_openai import ChatOpenAI

from copilot import settings

# Defaults match the original deployment.
DEFAULT_MODEL = "gpt-5.6-luna"
DEFAULT_BASE_URL = "https://tag-news-resource.services.ai.azure.com/openai/v1"
NO_KEY = "not-needed"  # OpenAI-compatible local servers ignore the key, but the client requires one


def base_url() -> str:
    return str(settings.get("llm", "base_url", "DFIR_LLM_BASE_URL", DEFAULT_BASE_URL))


def model_name() -> str:
    return str(settings.get("llm", "model", "DFIR_LLM_MODEL", DEFAULT_MODEL))


def is_local() -> bool:
    """A model on this machine or the private network: no API key, no internet needed."""
    if settings.flag("llm", "local", "DFIR_LLM_LOCAL"):
        return True
    host = urlparse(base_url()).hostname or ""
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def server_key() -> str:
    """A key configured on the server (never shown in the UI)."""
    return (os.environ.get("DFIR_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
            or str(settings.get("llm", "api_key", default="")))


def needs_user_key() -> bool:
    """Only a cloud endpoint without a server-side key asks the investigator for one."""
    return not server_key() and not is_local()


def make_llm(api_key: str = None) -> ChatOpenAI:
    """Builds the chat model. The key is passed directly, never written to os.environ."""
    return ChatOpenAI(
        model=model_name(),
        temperature=0,
        api_key=api_key or server_key() or (NO_KEY if is_local() else None),
        base_url=base_url(),
        timeout=float(settings.get("llm", "timeout", "DFIR_LLM_TIMEOUT", 300)),
    )
