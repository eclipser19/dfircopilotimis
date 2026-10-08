"""
Multiple investigations side by side, each bound to the accounts that may work on it.

Each case is a folder <cases_dir>/<case-id>/ with its case.yaml; its database and
outputs live in <data root>/<case-id>/ (see database.data_dir_for). Every investigator
session has its own active case (copilot/session.py); switching reloads that session's
case_config and case_db. The conversation must restart after a switch (the system prompt
describes the case); UIs check consume_switch() after each turn.

Access (when sign-in is used), in case.yaml:
    access:
      owner: alice          # whoever created the case
      members: [bob]        # added by the owner or an admin
Admins see every case. A case without an owner (e.g. made before sign-in) is visible to
admins only, until an admin assigns it. Without sign-in (CLI, or the app without
accounts) every case is accessible.
"""
import os
import re
from datetime import date

import yaml

from copilot import session
from copilot.case_config import CLIENT_ID_RE, case_config, cases_dir
from copilot.database import case_db, data_dir_for

CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
LEGACY_ID = "default"
CURRENT = object()   # default for `user` arguments: the current session's user


class CaseError(Exception):
    """Invalid case operation; the message is safe to show to the agent or user."""


def _case_file(case_id: str) -> str:
    if case_id == LEGACY_ID:
        return "case.yaml"
    return os.path.join(cases_dir(), case_id, "case.yaml")


def _id_for(path: str) -> str:
    folder = os.path.dirname(os.path.abspath(path))
    if os.path.dirname(folder) == os.path.abspath(cases_dir()):
        return os.path.basename(folder)
    return LEGACY_ID


def current_id() -> str:
    """The active case of this session (raises session.NoCase if none is open)."""
    return _id_for(case_config.path)


def _user(user):
    return session.current_user() if user is CURRENT else user


def access_of(data: dict) -> tuple:
    """(owner, members) from a case file's data."""
    access = data.get("access") or {}
    if not isinstance(access, dict):
        return "", []
    members = access.get("members") or []
    return str(access.get("owner") or ""), [str(m) for m in (members if isinstance(members, list) else [members])]


def can_access(case_id: str, user=CURRENT) -> bool:
    user = _user(user)
    if user is None:
        return True
    from copilot import auth
    if auth.is_admin(user):
        return True
    try:
        owner, members = access_of(_read(case_id))
    except CaseError:
        return False
    return user == owner or user in members


def can_manage(case_id: str, user=CURRENT) -> bool:
    """May change who has access: an admin or the owner (everyone without sign-in)."""
    user = _user(user)
    if user is None:
        return True
    from copilot import auth
    return auth.is_admin(user) or access_of(_read(case_id))[0] == user


def _all_ids() -> list:
    found = []
    root = cases_dir()
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            if CASE_ID_RE.match(name) and os.path.isfile(os.path.join(root, name, "case.yaml")):
                found.append(name)
    if os.path.isfile("case.yaml"):
        found.append(LEGACY_ID)
    return found


def list_cases(user=CURRENT) -> list:
    """The cases this user may open: id, name, owner, members, active flag, and whether it has data."""
    user = _user(user)
    try:
        active = current_id() if session.current().has_case else None
    except session.NoCase:
        active = None
    cases = []
    for case_id in _all_ids():
        if not can_access(case_id, user):
            continue
        path = _case_file(case_id)
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            data = {}
        owner, members = access_of(data)
        db_file = os.path.join(data_dir_for(path), "case.db")
        cases.append({
            "id": case_id,
            "name": (data.get("case", {}) or {}).get("name", case_id),
            "client_id": (data.get("velociraptor", {}) or {}).get("client_id", ""),
            "owner": owner,
            "members": members,
            "active": case_id == active,
            "has_data": os.path.isfile(db_file),
        })
    return cases


def _check(case_id: str) -> str:
    """The case file of a case this session's user may open (CaseError otherwise, without
    revealing whether a case they can't open exists)."""
    case_id = (case_id or "").strip()
    if not (case_id == LEGACY_ID or CASE_ID_RE.match(case_id)):
        raise CaseError(f"'{case_id}' is not a valid case ID (letters, digits, - and _).")
    path = _case_file(case_id)
    if not os.path.isfile(path) or not can_access(case_id):
        known = ", ".join(c["id"] for c in list_cases()) or "none"
        raise CaseError(f"No case '{case_id}'. Known cases: {known}.")
    return path


def switch(case_id: str) -> dict:
    """Makes another case active in this session. Raises CaseError if it doesn't exist or isn't allowed."""
    path = _check(case_id)
    current = session.current()
    current.open(path)
    current.switched = True
    return {"id": _id_for(path), "name": case_config.case_name, "data_dir": case_db.case_dir}


def consume_switch() -> bool:
    """True once after a switch: the caller must restart the conversation."""
    current = session.current()
    switched, current.switched = current.switched, False
    return switched


def new_session(user: str = None) -> "session.Session":
    """A session for a newly signed-in investigator, on the initial case if they may open it,
    else on their first case (or on no case, when they have none yet)."""
    from copilot.case_config import initial_case_file
    s = session.Session(user)
    if user is None:                       # no sign-in: everything is open, start where the CLI would
        s.open(initial_case_file())
        return s
    preferred = _id_for(initial_case_file())
    allowed = [c for c in _all_ids() if can_access(c, user)]
    if allowed:
        s.open(_case_file(preferred if preferred in allowed else allowed[0]))
    return s


def refresh() -> str:
    """
    Run at the start of each UI step: reloads the active case's settings if another session
    changed them, and closes the case if this session's user lost access to it. Returns a
    note for the investigator, or "".
    """
    current = session.current()
    if not current.has_case:
        return ""
    case_id = current_id()
    if not can_access(case_id):
        current.close()
        current.switched = True
        return f"You no longer have access to case '{case_id}'."
    current.reload_if_changed()
    return ""


def create(case_id: str, name: str, client_id: str = "", start_time: str = "", end_time: str = "",
           description: str = "", clock_offset_minutes: int = 0, iocs: dict = None,
           copy_from: str = None, dry_run: bool = False) -> str:
    """
    Creates cases/<case_id>/case.yaml from the template (does not switch to it); the current
    user owns it. Required: case_id and name. IOCs are validated; copy_from copies another
    case's collected data (same evidence client only; findings are not copied).
    """
    from copilot.iocs import clean
    if not (name or "").strip():
        raise CaseError("A case name is required.")
    if client_id and not CLIENT_ID_RE.match(client_id):
        raise CaseError(f"'{client_id}' is not a valid Velociraptor client ID (expected C.<hex>).")
    source = None
    if copy_from:
        _check(copy_from)
        source = _read(copy_from)
        source_client = (source.get("velociraptor", {}) or {}).get("client_id", "")
        if client_id and source_client and client_id != source_client:
            raise CaseError(f"Case '{copy_from}' is about client {source_client}, not {client_id}: "
                            f"data can only be copied between cases on the same evidence.")
        client_id = client_id or source_client
        # Checked before anything is written, so a failed copy never leaves a half-made case.
        if not os.path.isfile(os.path.join(data_dir_for(_case_file(copy_from)), "case.db")):
            raise CaseError(f"Case '{copy_from}' has no data yet.")
    from copilot.normalize import normalize_bound
    if not CASE_ID_RE.match(case_id or "") or case_id == LEGACY_ID:
        raise CaseError("Case ID must be 1-64 letters, digits, - or _ (and not 'default').")
    path = _case_file(case_id)
    if os.path.exists(path):
        raise CaseError(f"Case '{case_id}' already exists.")
    user = session.current_user()
    for label, value in (("start_time", start_time), ("end_time", end_time)):
        try:
            normalize_bound(value)
        except ValueError as e:
            raise CaseError(f"{label}: {e}")
    data = {
        "case": {"name": name or case_id, "analyst": user or "Investigator", "created": date.today().isoformat()},
        "velociraptor": {"client_id": client_id or "", "collection_wait_seconds": 300},
        "scope": {"start_time": start_time or "", "end_time": end_time or "",
                  "clock_offset_minutes": int(clock_offset_minutes or 0), "description": description or ""},
        "iocs": clean(iocs or {}),
        "collect": ["Generic.Client.Info", "Windows.EventLogs.RDPAuth", "Windows.Sys.StartupItems",
                    "Windows.Timeline.Prefetch", "Windows.System.TaskScheduler"],
        "collection": {"max_rows": 50000, "apply_time_window": True, "agent_collections": "confirm"},
        "output": {"report_formats": ["html"]},
        "agent": {"allow_raw_vql": False, "max_steps": 15, "max_tokens_per_turn": 300000,
                  "approvals": {"retract_finding": "confirm", "update_case": "confirm",
                                "switch_case": "confirm", "create_case": "confirm"}},
    }
    if user:
        data["access"] = {"owner": user, "members": []}
    if dry_run:
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Created by DFIR Copilot. Edit freely; see cases/szechuan/case.yaml for all options.\n")
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    if copy_from:
        copy_data(copy_from, case_id)
    return path


def _read(case_id: str) -> dict:
    """A case file's data (no access check: callers check first)."""
    path = _case_file(case_id)
    if not os.path.isfile(path):
        raise CaseError(f"No case '{case_id}'.")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# Settings the UI and the agent may change on an existing case.
EDITABLE = {"name", "client_id", "start_time", "end_time", "description", "clock_offset_minutes", "iocs"}


def update(case_id: str, dry_run: bool = False, **changes) -> dict:
    """
    Changes a case's settings (name, client_id, window, description, clock offset, IOCs).
    Rewrites its case.yaml (comments in the file are not kept). Reloads it if active.
    """
    from copilot.iocs import clean
    from copilot.normalize import normalize_bound
    unknown = set(changes) - EDITABLE
    if unknown:
        raise CaseError(f"Cannot change: {', '.join(sorted(unknown))}.")
    _check(case_id)
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
    if dry_run:
        return data
    _write(case_id, data)
    return data


def _write(case_id: str, data: dict):
    """Rewrites a case file and reloads it if it is this session's active case."""
    path = _case_file(case_id)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Managed by DFIR Copilot (edits from the app rewrite this file).\n")
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    current = session.current()
    if current.has_case and case_id == current_id():
        case_config.switch(path)
        current.touch()
        current.settings_changed = True


def set_access(case_id: str, members: list = None, owner: str = None) -> dict:
    """
    Changes who may work on a case: members (the owner or an admin), owner (an admin).
    Only the investigator does this, never the agent. Written to the case's audit log.
    """
    from copilot import auth
    _check(case_id)
    if not can_manage(case_id):
        raise CaseError("Only the case owner or an admin can change who has access.")
    data = _read(case_id)
    old_owner, old_members = access_of(data)
    new_owner = old_owner if owner is None else str(owner).strip()
    new_members = old_members if members is None else sorted({str(m).strip() for m in members if str(m).strip()})
    user = session.current_user()
    if new_owner != old_owner and user is not None and not auth.is_admin(user):
        raise CaseError("Only an admin can change the case owner.")
    known = set(auth.usernames())
    unknown = [u for u in [new_owner, *new_members] if u and known and u not in known]
    if unknown:
        raise CaseError(f"No such account: {', '.join(unknown)}.")
    new_members = [m for m in new_members if m != new_owner]
    data["access"] = {"owner": new_owner, "members": new_members}
    _write(case_id, data)
    _audit(case_id, "case_access", f"owner {old_owner or '-'} -> {new_owner or '-'}; "
                                  f"members {old_members} -> {new_members}")
    return data["access"]


def _audit(case_id: str, tool: str, text: str):
    current = session.current()
    if current.has_case and case_id == current_id():
        case_db.log_query(tool, text, 0)
        return
    from copilot.database import CaseDatabase
    db = CaseDatabase(data_dir_for(_case_file(case_id)))
    try:
        db.log_query(tool, text, 0)
    finally:
        db.conn.close()


def consume_settings_change() -> bool:
    """True once after the active case's settings changed: refresh the system prompt."""
    current = session.current()
    changed, current.settings_changed = current.settings_changed, False
    return changed


def copy_data(source_id: str, target_id: str) -> dict:
    """
    Copies collected data (records, timeline, search index, collections) from one case to
    another on the same evidence client. Findings, outputs and the audit trail stay behind;
    the copy itself is written to the target's audit log.
    """
    import sqlite3
    from copilot.database import CaseDatabase
    _check(source_id)
    _check(target_id)
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
    if session.current_user() is not None:
        return ""   # the hint names server paths: only for a single investigator without sign-in
    case_id = current_id()
    if case_id == LEGACY_ID or os.environ.get("DFIR_CASE_DIR") or not os.path.isfile(legacy):
        return ""
    target = os.path.join(root, case_id)
    if case_db.get_stats()["total_records"] or case_db.get_collections() or case_db.get_findings(True):
        return ""
    return (f"Found {legacy} from before cases were separated. If it belongs to case '{case_id}', stop the "
            f"copilot and move it (and its outputs folder) into {target}{os.sep}.")
