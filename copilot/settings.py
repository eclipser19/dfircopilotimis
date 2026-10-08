"""
Server settings in one file: server.yaml next to app.py (or the path in DFIR_SETTINGS).
It is git-ignored; copy server.example.yaml to start. Environment variables, when set,
win over the file, so existing setups keep working.

    llm:
      base_url: http://localhost:11434/v1   # DFIR_LLM_BASE_URL
      model: qwen3:32b                      # DFIR_LLM_MODEL
      api_key: ""                           # DFIR_LLM_API_KEY (or OPENAI_API_KEY)
      local: false                          # DFIR_LLM_LOCAL
      timeout: 300                          # DFIR_LLM_TIMEOUT
    login:
      required: true                        # DFIR_REQUIRE_LOGIN

The file is re-read when it changes, so the app picks up edits on the next page load.
"""
import os

import yaml

_cache = {"path": None, "mtime": None, "data": {}}


def settings_file() -> str:
    return os.environ.get("DFIR_SETTINGS", "server.yaml")


def _load() -> dict:
    path = settings_file()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if _cache["path"] != path or _cache["mtime"] != mtime:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        _cache.update(path=path, mtime=mtime, data=data if isinstance(data, dict) else {})
    return _cache["data"]


def get(section: str, key: str, env: str = None, default=None):
    """The environment variable if set, else server.yaml's section.key, else the default."""
    if env and os.environ.get(env, "") != "":
        return os.environ[env]
    value = (_load().get(section) or {}).get(key)
    return default if value is None or value == "" else value


def flag(section: str, key: str, env: str = None) -> bool:
    value = get(section, key, env, False)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")
