"""
Checks case.yaml and server.yaml against the settings the copilot knows, so a misspelt key or a
value of the wrong type is reported in words instead of being silently ignored (Velociraptor-style
"unknown keys do nothing"). Files with problems still load: old case files keep working, and the
problems are shown in the CLI at start, in the app's sidebar and by the selftest.

    python -m copilot.config_check                 # server.yaml and every cases/*/case.yaml
    python -m copilot.config_check path/case.yaml  # one file (exit code 1 if it has problems)
"""
import difflib
import os
import sys
from datetime import date, datetime

import yaml

from copilot.approvals import ACTIONS, MODES

TEXT = (str,)
INT = "int"
NUMBER = "number"
BOOL = (bool,)
LIST = (list,)
TIME = (str, datetime, date)          # YAML reads an unquoted 2020-09-18T00:00:00Z as a datetime


def one_of(*values):
    return ("one_of", values)


CASE_SCHEMA = {
    "case": {"name": TEXT, "analyst": TEXT, "created": TIME},
    "velociraptor": {"client_id": TEXT, "collection_wait_seconds": INT},
    "scope": {"start_time": TIME, "end_time": TIME, "clock_offset_minutes": INT, "description": TEXT},
    "iocs": {"hashes": LIST, "ips": LIST, "domains": LIST, "filenames": LIST, "users": LIST},
    "memory": {"image": TEXT, "os": one_of("windows", "linux"), "collect": LIST},
    "collect": LIST,
    "collection": {"max_rows": INT, "apply_time_window": BOOL, "agent_collections": one_of(*MODES)},
    "artifacts": {"allow": LIST},
    "output": {"report_formats": LIST, "dir": TEXT, "confirmed_findings_only": BOOL},
    "agent": {"allow_raw_vql": BOOL, "max_steps": INT, "max_tokens_per_turn": INT,
              "investigate_steps": INT, "investigate_tokens": INT,
              "approvals": {kind: one_of(*MODES) for kind in ACTIONS}},
    "access": {"owner": TEXT, "members": LIST, "shared_with": LIST, "share_findings": BOOL},
    "evidence": {"image_name": TEXT, "image_sha256": TEXT, "image_md5": TEXT, "acquired": TIME,
                 "notes": TEXT},
}

SERVER_SCHEMA = {
    "llm": {"base_url": TEXT, "model": TEXT, "api_key": TEXT, "local": BOOL, "timeout": NUMBER},
    "login": {"required": BOOL, "new_evidence": one_of("anyone", "admins")},
    "memory": {"images_dir": TEXT, "symbols_dir": TEXT, "offline": BOOL, "timeout": NUMBER,
               "yara_dir": TEXT, "command": TEXT},
    "knowledge": {"learned_file": TEXT},
    "report": {"confirmed_findings_only": BOOL},
}


def _type_problem(value, spec) -> str:
    if value is None or value == "":
        return ""                             # empty means "use the default" everywhere
    if spec == INT:
        ok = isinstance(value, int) and not isinstance(value, bool)
        return "" if ok else "a whole number"
    if spec == NUMBER:
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        return "" if ok else "a number"
    if isinstance(spec, tuple) and spec and spec[0] == "one_of":
        return "" if str(value).lower() in spec[1] else "one of " + ", ".join(spec[1])
    if isinstance(spec, tuple):
        return "" if isinstance(value, spec) else {
            BOOL: "true or false", LIST: "a list", TEXT: "text", TIME: "a time (ISO 8601)"}.get(spec, "another type")
    return ""


def check(data, schema: dict, where: str = "") -> list:
    """Problems as sentences: unknown keys (with the closest known one) and values of the wrong type."""
    problems = []
    if data is None:
        return problems
    if not isinstance(data, dict):
        return [f"{where or 'the file'} should be a mapping of settings, not {type(data).__name__}"]
    for key, value in data.items():
        path = f"{where}.{key}" if where else str(key)
        if key not in schema:
            close = difflib.get_close_matches(str(key), [str(k) for k in schema], n=1, cutoff=0.6)
            hint = f" (did you mean '{close[0]}'?)" if close else ""
            problems.append(f"unknown setting '{path}'{hint}: it is ignored")
            continue
        spec = schema[key]
        if isinstance(spec, dict):
            if value is not None and not isinstance(value, dict):
                problems.append(f"'{path}' should be a section of settings, not {type(value).__name__}")
            else:
                problems += check(value, spec, path)
            continue
        expected = _type_problem(value, spec)
        if expected:
            problems.append(f"'{path}' should be {expected}, not {value!r}")
    return problems


def _load(path: str):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def check_file(path: str, schema: dict = None) -> list:
    """Problems of one settings file ([] if it is fine or missing)."""
    if not os.path.isfile(path):
        return []
    if schema is None:
        schema = SERVER_SCHEMA if os.path.basename(path).startswith("server") else CASE_SCHEMA
    try:
        data = _load(path)
    except yaml.YAMLError as e:
        return [f"not valid YAML: {str(e).splitlines()[0]}"]
    return check(data, schema)


def case_problems(case_config) -> list:
    return check(case_config.data, CASE_SCHEMA)


def server_problems() -> list:
    from copilot.settings import settings_file
    return check_file(settings_file(), SERVER_SCHEMA)


def main(argv=None) -> int:
    from copilot.case_config import cases_dir
    from copilot.settings import settings_file
    paths = list(argv if argv is not None else sys.argv[1:])
    if not paths:
        paths = [settings_file()] + sorted(
            os.path.join(cases_dir(), d, "case.yaml") for d in (os.listdir(cases_dir()) if os.path.isdir(cases_dir()) else [])
            if os.path.isfile(os.path.join(cases_dir(), d, "case.yaml")))
    bad = 0
    for path in paths:
        problems = check_file(path)
        if not os.path.isfile(path):
            print(f"[-] {path}: not found")
            continue
        print(f"[{'!' if problems else '+'}] {path}" + ("" if problems else ": OK"))
        for problem in problems:
            print(f"    {problem}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
