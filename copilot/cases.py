"""
Multiple investigations side by side.

Each case is a folder <cases_dir>/<case-id>/ with its case.yaml; its database and
outputs live in <data root>/<case-id>/ (see database.data_dir_for). Switching a case
reloads the shared case_config and case_db in place, so every module sees the new case.
The conversation must restart after a switch (the system prompt describes the case);
UIs check consume_switch() after each turn.

Note: the active case is process-wide. The Streamlit app is meant for one investigator
at a time.
"""
import os
import re
from datetime import date

import yaml

from copilot.case_config import case_config, cases_dir
from copilot.database import case_db, data_dir_for

CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
LEGACY_ID = "default"

_switched = False


class CaseError(Exception):
    """Invalid case operation; the message is safe to show to the agent or user."""


def _case_file(case_id: str) -> str:
    if case_id == LEGACY_ID:
        return "case.yaml"
    return os.path.join(cases_dir(), case_id, "case.yaml")


def current_id() -> str:
    folder = os.path.dirname(os.path.abspath(case_config.path))
    if os.path.dirname(folder) == os.path.abspath(cases_dir()):
        return os.path.basename(folder)
    return LEGACY_ID


def list_cases() -> list:
    """Every case: id, name, active flag, and whether it has data yet."""
    found = []
    root = cases_dir()
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            if CASE_ID_RE.match(name) and os.path.isfile(os.path.join(root, name, "case.yaml")):
                found.append(name)
    if os.path.isfile("case.yaml"):
        found.append(LEGACY_ID)
    active = current_id()
    cases = []
    for case_id in found:
        path = _case_file(case_id)
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            data = {}
        db_file = os.path.join(data_dir_for(path), "case.db")
        cases.append({
            "id": case_id,
            "name": (data.get("case", {}) or {}).get("name", case_id),
            "client_id": (data.get("velociraptor", {}) or {}).get("client_id", ""),
            "active": case_id == active,
            "has_data": os.path.isfile(db_file),
        })
    return cases


def switch(case_id: str) -> dict:
    """Makes another case active. Raises CaseError if it doesn't exist."""
    global _switched
    case_id = (case_id or "").strip()
    if not (case_id == LEGACY_ID or CASE_ID_RE.match(case_id)):
        raise CaseError(f"'{case_id}' is not a valid case ID (letters, digits, - and _).")
    path = _case_file(case_id)
    if not os.path.isfile(path):
        known = ", ".join(c["id"] for c in list_cases()) or "none"
        raise CaseError(f"No case '{case_id}'. Known cases: {known}.")
    case_config.switch(path)
    case_db.open(data_dir_for(path))
    _switched = True
    return {"id": case_id, "name": case_config.case_name, "data_dir": case_db.case_dir}


def consume_switch() -> bool:
    """True once after a switch: the caller must restart the conversation."""
    global _switched
    switched, _switched = _switched, False
    return switched


def create(case_id: str, name: str, client_id: str = "", start_time: str = "", end_time: str = "",
           description: str = "", clock_offset_minutes: int = 0) -> str:
    """Creates cases/<case_id>/case.yaml from the template (does not switch to it)."""
    from copilot.normalize import normalize_bound
    if not CASE_ID_RE.match(case_id or "") or case_id == LEGACY_ID:
        raise CaseError("Case ID must be 1-64 letters, digits, - or _ (and not 'default').")
    path = _case_file(case_id)
    if os.path.exists(path):
        raise CaseError(f"Case '{case_id}' already exists.")
    for label, value in (("start_time", start_time), ("end_time", end_time)):
        try:
            normalize_bound(value)
        except ValueError as e:
            raise CaseError(f"{label}: {e}")
    data = {
        "case": {"name": name or case_id, "analyst": "Investigator", "created": date.today().isoformat()},
        "velociraptor": {"client_id": client_id or "", "collection_wait_seconds": 300},
        "scope": {"start_time": start_time or "", "end_time": end_time or "",
                  "clock_offset_minutes": int(clock_offset_minutes or 0), "description": description or ""},
        "iocs": {"hashes": [], "ips": [], "domains": [], "filenames": [], "users": []},
        "collect": ["Generic.Client.Info", "Windows.EventLogs.RDPAuth", "Windows.Sys.StartupItems",
                    "Windows.Timeline.Prefetch", "Windows.System.TaskScheduler"],
        "collection": {"max_rows": 50000, "apply_time_window": True, "agent_collections": "confirm"},
        "output": {"report_formats": ["html"]},
        "agent": {"allow_raw_vql": False, "max_steps": 15, "max_tokens_per_turn": 300000},
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Created by DFIR Copilot. Edit freely; see cases/szechuan/case.yaml for all options.\n")
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    return path


def legacy_data_hint() -> str:
    """
    Before cases were separated, every case used case_data/case.db. If that file exists
    and the active case has no database yet, tell the investigator how to move it.
    """
    root = os.environ.get("DFIR_DATA_DIR", "case_data")
    legacy = os.path.join(root, "case.db")
    case_id = current_id()
    if case_id == LEGACY_ID or os.environ.get("DFIR_CASE_DIR") or not os.path.isfile(legacy):
        return ""
    target = os.path.join(root, case_id)
    if case_db.get_stats()["total_records"] or case_db.get_collections() or case_db.get_findings(True):
        return ""
    return (f"Found {legacy} from before cases were separated. If it belongs to case '{case_id}', stop the "
            f"copilot and move it (and its outputs folder) into {target}{os.sep}.")
