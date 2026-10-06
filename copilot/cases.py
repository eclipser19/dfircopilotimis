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

from copilot.case_config import CLIENT_ID_RE, case_config, cases_dir
from copilot.database import case_db, data_dir_for

CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
LEGACY_ID = "default"

_switched = False
_settings_changed = False


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
           description: str = "", clock_offset_minutes: int = 0, iocs: dict = None,
           copy_from: str = None) -> str:
    """
    Creates cases/<case_id>/case.yaml from the template (does not switch to it).
    Required: case_id and name. IOCs are validated; copy_from copies another case's
    collected data (same evidence client only; findings are not copied).
    """
    from copilot.iocs import clean
    if not (name or "").strip():
        raise CaseError("A case name is required.")
    if client_id and not CLIENT_ID_RE.match(client_id):
        raise CaseError(f"'{client_id}' is not a valid Velociraptor client ID (expected C.<hex>).")
    source = None
    if copy_from:
        source = _read(copy_from)
        source_client = (source.get("velociraptor", {}) or {}).get("client_id", "")
        if client_id and source_client and client_id != source_client:
            raise CaseError(f"Case '{copy_from}' is about client {source_client}, not {client_id}: "
                            f"data can only be copied between cases on the same evidence.")
        client_id = client_id or source_client
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
        "iocs": clean(iocs or {}),
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
    if copy_from:
        copy_data(copy_from, case_id)
    return path


def _read(case_id: str) -> dict:
    path = _case_file(case_id)
    if not os.path.isfile(path):
        raise CaseError(f"No case '{case_id}'.")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# Settings the UI and the agent may change on an existing case.
EDITABLE = {"name", "client_id", "start_time", "end_time", "description", "clock_offset_minutes", "iocs"}


def update(case_id: str, **changes) -> dict:
    """
    Changes a case's settings (name, client_id, window, description, clock offset, IOCs).
    Rewrites its case.yaml (comments in the file are not kept). Reloads it if active.
    """
    global _settings_changed
    from copilot.iocs import clean
    from copilot.normalize import normalize_bound
    unknown = set(changes) - EDITABLE
    if unknown:
        raise CaseError(f"Cannot change: {', '.join(sorted(unknown))}.")
    data = _read(case_id)
    if "name" in changes:
        if not str(changes["name"]).strip():
            raise CaseError("A case name is required.")
        data.setdefault("case", {})["name"] = str(changes["name"]).strip()
    if "client_id" in changes:
        cid = str(changes["client_id"] or "").strip()
        if cid and not CLIENT_ID_RE.match(cid):
            raise CaseError(f"'{cid}' is not a valid Velociraptor client ID (expected C.<hex>).")
        data.setdefault("velociraptor", {})["client_id"] = cid
    scope = data.setdefault("scope", {})
    for key in ("start_time", "end_time"):
        if key in changes:
            try:
                normalize_bound(changes[key])
            except ValueError as e:
                raise CaseError(f"{key}: {e}")
            scope[key] = changes[key] or ""
    if "description" in changes:
        scope["description"] = changes["description"] or ""
    if "clock_offset_minutes" in changes:
        scope["clock_offset_minutes"] = int(changes["clock_offset_minutes"] or 0)
    if "iocs" in changes:
        data["iocs"] = clean(changes["iocs"])
    path = _case_file(case_id)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Managed by DFIR Copilot (edits from the app rewrite this file).\n")
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    if case_id == current_id():
        case_config.switch(path)
        _settings_changed = True
    return data


def consume_settings_change() -> bool:
    """True once after the active case's settings changed: refresh the system prompt."""
    global _settings_changed
    changed, _settings_changed = _settings_changed, False
    return changed


def copy_data(source_id: str, target_id: str) -> dict:
    """
    Copies collected data (records, timeline, search index, collections) from one case to
    another on the same evidence client. Findings, outputs and the audit trail stay behind;
    the copy itself is written to the target's audit log.
    """
    import sqlite3
    from copilot.database import CaseDatabase
    source_data, target_data = _read(source_id), _read(target_id)
    src_client = (source_data.get("velociraptor", {}) or {}).get("client_id", "")
    dst_client = (target_data.get("velociraptor", {}) or {}).get("client_id", "")
    if src_client and dst_client and src_client != dst_client:
        raise CaseError(f"Cases are on different evidence clients ({src_client} vs {dst_client}).")
    src_db = os.path.join(data_dir_for(_case_file(source_id)), "case.db")
    if not os.path.isfile(src_db):
        raise CaseError(f"Case '{source_id}' has no data yet.")
    target = CaseDatabase(data_dir_for(_case_file(target_id)))
    counts = {}
    try:
        target.conn.execute("ATTACH DATABASE ? AS src", (src_db,))
        for table in ("records", "timeline", "collections"):
            before = target.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            target.conn.execute(f"INSERT OR IGNORE INTO {table} SELECT * FROM src.{table}")
            counts[table] = target.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] - before
        if target.has_fts:
            try:
                target.conn.execute("INSERT INTO records_fts (evidence_id, text) SELECT s.evidence_id, s.text "
                                    "FROM src.records_fts s WHERE s.evidence_id NOT IN "
                                    "(SELECT evidence_id FROM records_fts)")
            except sqlite3.OperationalError:
                pass
        target.conn.commit()
        target.conn.execute("DETACH DATABASE src")
        target.log_query("copy_case_data", f"from case {source_id} ({src_db})", counts["records"])
    finally:
        target.conn.close()
    return counts


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
