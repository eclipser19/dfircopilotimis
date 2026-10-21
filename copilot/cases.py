"""
Multiple investigations side by side, each bound to the accounts that may work on it.

Each case is a folder <cases_dir>/<case-id>/ with its case.yaml and, in data/, its database,
chats and outputs (see database.data_dir_for; DFIR_DATA_DIR keeps the data elsewhere). Every investigator
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

Sharing (access.shared_with: accounts, or "*" for every account; access.share_findings) lets
others start their own case from a case's evidence without opening it: copy its collected data,
and its findings and dossier if shared too. Copies stay theirs when sharing is withdrawn.

Evidence sources (a Velociraptor client, a memory image) are protected too, not only case
folders: a case may name a source only if no case uses it yet, or if the user can open one of
the cases that use it or has it shared with them (an admin may name any). `login.new_evidence: admins` in server.yaml
keeps unused sources for admins. Once a case holds data from a source, its settings can't be
pointed at another one: that would mix two machines' evidence in one database.
"""
import os
import re
from datetime import date

import yaml

from copilot import session
from copilot.case_config import CLIENT_ID_RE, case_config, cases_dir
from copilot.database import CASE_DATA_FOLDER, LEGACY_DATA_ROOT, case_db, data_dir_for

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


EVERYONE = "*"


def sharing_of(data: dict) -> tuple:
    """(shared_with, share_findings) from a case file's data; shared_with ["*"] = every account."""
    access = data.get("access") or {}
    if not isinstance(access, dict):
        return [], False
    shared = access.get("shared_with") or []
    shared = [str(u) for u in (shared if isinstance(shared, list) else [shared])]
    return shared, bool(access.get("share_findings"))


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


def can_reuse(case_id: str, user=CURRENT, findings: bool = False) -> bool:
    """
    May start from this case's evidence: name its client or memory image, copy its collected data
    (and, with findings=True, its findings and dossier) into a case of their own. Members can; others
    only if the owner shares the case with them or with everyone (access.shared_with). Sharing never
    opens the case itself: its chats, files and audit log stay with its members.
    """
    if can_access(case_id, user):
        return True
    user = _user(user)
    try:
        shared_with, share_findings = sharing_of(_read(case_id))
    except CaseError:
        return False
    return (EVERYONE in shared_with or user in shared_with) and (share_findings or not findings)


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


def reusable_cases(user=CURRENT) -> list:
    """Cases with collected data this user may start from: their own (shared: False) and those
    shared with them, with what each allows (findings: its findings and dossier too)."""
    user = _user(user)
    out = []
    for case_id in _all_ids():
        if not can_reuse(case_id, user):
            continue
        path = _case_file(case_id)
        if not os.path.isfile(os.path.join(data_dir_for(path), "case.db")):
            continue
        try:
            data = _read(case_id)
        except (CaseError, OSError, yaml.YAMLError):
            continue
        sources = _sources(data)
        out.append({"id": case_id, "name": (data.get("case") or {}).get("name", case_id),
                    "owner": access_of(data)[0], "client_id": sources.get("client", ""),
                    "memory_image": sources.get("memory", ""), "shared": not can_access(case_id, user),
                    "findings": can_reuse(case_id, user, findings=True)})
    return out


def _check(case_id: str, reuse: bool = False) -> str:
    """The case file of a case this session's user may open (CaseError otherwise, without
    revealing whether a case they can't open exists). reuse=True: or one shared with them."""
    case_id = (case_id or "").strip()
    if not (case_id == LEGACY_ID or CASE_ID_RE.match(case_id)):
        raise CaseError(f"'{case_id}' is not a valid case ID (letters, digits, - and _).")
    path = _case_file(case_id)
    if not os.path.isfile(path) or not (can_reuse(case_id) if reuse else can_access(case_id)):
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


def _check_memory_image(name: str) -> str:
    """A memory image from the server's memory folder, or "" (none)."""
    name = (name or "").strip()
    if not name:
        return ""
    from copilot import memory
    if name not in {i["name"] for i in memory.available_images()}:
        raise CaseError(f"No memory image '{name}' in the server's memory folder"
                        f"{'' if memory.images_dir() else ' (memory.images_dir is not set in server.yaml)'}.")
    return name


# ---------------------------------------------------------------- evidence sources
SOURCE_LABELS = {"client": "Velociraptor client", "memory": "memory image"}
MEMORY_SOURCE = "memory:"          # how memory runs name their source in the database (memory.execute)


def _sources(data: dict) -> dict:
    """The evidence a case file points at: {"client": "C.<id>", "memory": "<image>"}, empty ones left out."""
    vr, mem = data.get("velociraptor") or {}, data.get("memory") or {}
    found = {"client": str(vr.get("client_id") or "").strip() if isinstance(vr, dict) else "",
             "memory": str(mem.get("image") or "").strip() if isinstance(mem, dict) else ""}
    return {kind: value for kind, value in found.items() if value}


def _same_source(kind: str, a, b) -> bool:
    a, b = str(a or "").strip(), str(b or "").strip()
    if not (a and b):
        return False
    if kind == "client":
        return a.lower() == b.lower()
    return os.path.normcase(a.replace("\\", "/")) == os.path.normcase(b.replace("\\", "/"))


def _case_sources() -> list:
    """(case_id, sources) of every case, whoever owns it: read once per check."""
    found = []
    for case_id in _all_ids():
        try:
            found.append((case_id, _sources(_read(case_id))))
        except (CaseError, OSError, yaml.YAMLError):
            continue
    return found


def new_evidence_policy() -> str:
    """Who may open the first case on a source: anyone (default) or admins (login.new_evidence)."""
    from copilot import settings
    policy = str(settings.get("login", "new_evidence", "DFIR_NEW_EVIDENCE", "anyone") or "anyone").lower()
    return "admins" if policy == "admins" else "anyone"


def source_problem(kind: str, value: str, user=CURRENT, index: list = None) -> str:
    """Why this user may not point a case at this evidence source ("" = they may)."""
    user = _user(user)
    if not str(value or "").strip() or user is None:
        return ""
    from copilot import auth
    if auth.is_admin(user):
        return ""
    using = [case_id for case_id, sources in (index if index is not None else _case_sources())
             if _same_source(kind, sources.get(kind), value)]
    if any(can_reuse(case_id, user) for case_id in using):
        return ""
    label = SOURCE_LABELS[kind]
    if using:
        return (f"The {label} {value} is evidence in an investigation you are not part of. Ask the owner "
                f"of a case on it, or an admin, to add you to that case or share it with you.")
    if new_evidence_policy() == "admins":
        return f"Only an admin can open the first case on new evidence ({label} {value})."
    return ""


def usable_memory_images(user=CURRENT) -> list:
    """The server's memory images this user may put in a case ([{name, size}])."""
    from copilot import memory
    index = _case_sources()
    return [i for i in memory.available_images() if not source_problem("memory", i["name"], user, index)]


def collected_sources(case_id: str) -> dict:
    """The evidence this case's database already holds data from: {"client": [...], "memory": [...]}."""
    import sqlite3
    db_file = os.path.join(data_dir_for(_case_file(case_id)), "case.db")
    held = {"client": [], "memory": []}
    if not os.path.isfile(db_file):
        return held
    conn = sqlite3.connect(db_file, timeout=60)
    try:
        rows = conn.execute("SELECT DISTINCT client_id FROM collections WHERE rows_ingested > 0").fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    for (source,) in rows:
        source = str(source or "")
        if source.startswith(MEMORY_SOURCE):
            held["memory"].append(source[len(MEMORY_SOURCE):])
        elif source:
            held["client"].append(source)
    return held


def _check_sources(case_id: str, before: dict, after: dict):
    """A case's new evidence sources must be the user's to use, and must not replace the source
    its data came from (CaseError)."""
    index = None
    for kind, value in after.items():
        if _same_source(kind, before.get(kind), value):
            continue
        index = index if index is not None else _case_sources()
        problem = source_problem(kind, value, index=index)
        if problem:
            raise CaseError(problem)
        if case_id:
            other = [s for s in collected_sources(case_id)[kind] if not _same_source(kind, s, value)]
            if other:
                label = SOURCE_LABELS[kind]
                raise CaseError(f"This case already holds data from {label} {', '.join(other)}: pointing it at "
                                f"{value} would mix two sources' evidence in one case. Create a new case for {value}.")


def create(case_id: str, name: str, client_id: str = "", start_time: str = "", end_time: str = "",
           description: str = "", clock_offset_minutes: int = 0, iocs: dict = None,
           copy_from: str = None, dry_run: bool = False, memory_image: str = "", memory_os: str = "windows",
           copy_findings: bool = False) -> str:
    """
    Creates cases/<case_id>/case.yaml from the template (does not switch to it); the current
    user owns it. Required: case_id and name. IOCs are validated; copy_from copies another
    case's collected data (one of the user's or shared with them; same evidence only), and with
    copy_findings its findings and dossier too. The new case is on that case's evidence.
    """
    from copilot.iocs import clean
    if not (name or "").strip():
        raise CaseError("A case name is required.")
    if client_id and not CLIENT_ID_RE.match(client_id):
        raise CaseError(f"'{client_id}' is not a valid Velociraptor client ID (expected C.<hex>).")
    source = None
    if copy_from:
        _check(copy_from, reuse=True)
        source = _read(copy_from)
        source_client = (source.get("velociraptor", {}) or {}).get("client_id", "")
        if client_id and source_client and client_id != source_client:
            raise CaseError(f"Case '{copy_from}' is about client {source_client}, not {client_id}: "
                            f"data can only be copied between cases on the same evidence.")
        client_id = client_id or source_client
        memory_image = memory_image or _sources(source).get("memory", "")
        # Checked before anything is written, so a failed copy never leaves a half-made case.
        if not os.path.isfile(os.path.join(data_dir_for(_case_file(copy_from)), "case.db")):
            raise CaseError(f"Case '{copy_from}' has no data yet.")
        if copy_findings and not can_reuse(copy_from, findings=True):
            raise CaseError(f"Case '{copy_from}' is shared without its findings: only its collected data can be copied.")
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
    memory_image = _check_memory_image(memory_image)
    data = {
        "case": {"name": name or case_id, "analyst": user or "Investigator", "created": date.today().isoformat()},
        "velociraptor": {"client_id": client_id or "", "collection_wait_seconds": 300},
        "scope": {"start_time": start_time or "", "end_time": end_time or "",
                  "clock_offset_minutes": int(clock_offset_minutes or 0), "description": description or ""},
        "iocs": clean(iocs or {}),
        "memory": {"image": memory_image, "os": memory_os if memory_os in ("windows", "linux") else "windows"},
        "collect": ["Generic.Client.Info", "Windows.EventLogs.RDPAuth", "Windows.Sys.StartupItems",
                    "Windows.Timeline.Prefetch", "Windows.System.TaskScheduler"],
        "collection": {"max_rows": 50000, "apply_time_window": True, "agent_collections": "confirm"},
        "output": {"report_formats": ["html"]},
        "agent": {"allow_raw_vql": False, "max_steps": 20, "max_tokens_per_turn": 300000,
                  "approvals": {"retract_finding": "confirm", "update_case": "confirm",
                                "switch_case": "confirm", "create_case": "confirm", "memory": "confirm"}},
    }
    if user:
        data["access"] = {"owner": user, "members": []}
    _check_sources(None, {}, _sources(data))
    if dry_run:
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Created by DFIR Copilot. Edit freely; see cases/szechuan/case.yaml for all options.\n")
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    if copy_from:
        copy_data(copy_from, case_id, findings=copy_findings)
    return path


def _read(case_id: str) -> dict:
    """A case file's data (no access check: callers check first)."""
    path = _case_file(case_id)
    if not os.path.isfile(path):
        raise CaseError(f"No case '{case_id}'.")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# Settings the UI and the agent may change on an existing case.
EDITABLE = {"name", "client_id", "start_time", "end_time", "description", "clock_offset_minutes", "iocs",
            "memory_image", "memory_os", "collect", "memory_collect", "evidence"}
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$")


def _check_triage(entries) -> list:
    """The disk triage list as stored in case.yaml: names, or {artifact, parameters} when there are any."""
    import fnmatch
    from copilot.case_config import ARTIFACT_DENYLIST
    out = []
    for entry in entries or []:
        name, params = (entry, {}) if isinstance(entry, str) else \
            ((entry or {}).get("artifact"), (entry or {}).get("parameters") or {})
        name = str(name or "").strip()
        if not ARTIFACT_NAME_RE.match(name):
            raise CaseError(f"'{name}' is not a Velociraptor artifact name.")
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in ARTIFACT_DENYLIST):
            raise CaseError(f"'{name}' can never be collected by the copilot.")
        if not isinstance(params, dict):
            raise CaseError(f"Parameters of {name} must be name: value pairs.")
        out.append({"artifact": name, "parameters": {str(k): str(v) for k, v in params.items()}} if params else name)
    return out


def _check_memory_triage(plugins) -> list:
    from copilot import memory
    try:
        names = [memory.resolve(p)[0] for p in plugins or []]
    except memory.MemoryAnalysisError as e:
        raise CaseError(str(e))
    searches = [n for n in names if memory.PLUGINS[n].searches]
    if searches:
        raise CaseError(f"{', '.join(searches)} search memory for a text or rules, so they can't be part of the "
                        f"triage. Ask the agent to search for what you are looking for.")
    return names


def update(case_id: str, dry_run: bool = False, **changes) -> dict:
    """
    Changes a case's settings (name, client_id, window, description, clock offset, IOCs).
    Rewrites its case.yaml (comments in the file are not kept). Reloads it if active.
    A new client or memory image must be one the user may use, and can't replace the source
    the case already holds data from.
    """
    from copilot.iocs import clean
    from copilot.normalize import normalize_bound
    unknown = set(changes) - EDITABLE
    if unknown:
        raise CaseError(f"Cannot change: {', '.join(sorted(unknown))}.")
    _check(case_id)
    data = _read(case_id)
    before = _sources(data)
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
    if "memory_image" in changes:
        data.setdefault("memory", {})["image"] = _check_memory_image(changes["memory_image"])
    if "memory_os" in changes:
        if changes["memory_os"] not in ("windows", "linux"):
            raise CaseError("memory_os must be windows or linux.")
        data.setdefault("memory", {})["os"] = changes["memory_os"]
    if "collect" in changes:
        data["collect"] = _check_triage(changes["collect"])
    if "memory_collect" in changes:
        data.setdefault("memory", {})["collect"] = _check_memory_triage(changes["memory_collect"])
    if "evidence" in changes:
        data["evidence"] = _check_evidence(changes["evidence"], data.get("evidence"))
        if not data["evidence"]:
            del data["evidence"]
    after = _sources(data)
    _check_sources(case_id, before, after)
    if dry_run:
        return data
    _write(case_id, data)
    moved = [f"{SOURCE_LABELS[k]} {before.get(k) or '-'} -> {after.get(k) or '-'}"
             for k in SOURCE_LABELS if not _same_source(k, before.get(k), after.get(k))
             and (before.get(k) or after.get(k))]
    if moved and os.path.isfile(os.path.join(data_dir_for(_case_file(case_id)), "case.db")):
        _audit(case_id, "case_evidence", "; ".join(moved))
    return data


EVIDENCE_FIELDS = {"image_name": None, "image_sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
                   "image_md5": re.compile(r"^[0-9a-fA-F]{32}$"), "acquired": None, "notes": None}


def _check_evidence(values: dict, old) -> dict:
    """The case file's `evidence` section (what the disk image is, for the report): known fields,
    hashes as hex; empty values are dropped."""
    merged = dict(old) if isinstance(old, dict) else {}
    for key, value in (values or {}).items():
        if key not in EVIDENCE_FIELDS:
            raise CaseError(f"Unknown evidence field '{key}' (known: {', '.join(EVIDENCE_FIELDS)}).")
        value = str(value or "").strip()
        pattern = EVIDENCE_FIELDS[key]
        if value and pattern and not pattern.match(value):
            raise CaseError(f"{key} must be {'64' if key.endswith('sha256') else '32'} hexadecimal characters.")
        if value:
            merged[key] = value.lower() if pattern else value
        else:
            merged.pop(key, None)
    return merged


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
    access = data["access"] if isinstance(data.get("access"), dict) else {}
    access.update(owner=new_owner, members=new_members)          # sharing settings stay
    data["access"] = access
    _write(case_id, data)
    _audit(case_id, "case_access", f"owner {old_owner or '-'} -> {new_owner or '-'}; "
                                  f"members {old_members} -> {new_members}")
    return {"owner": new_owner, "members": new_members}


def set_sharing(case_id: str, shared_with: list, findings: bool = False) -> dict:
    """
    Lets others start their own case from this one's evidence (the owner or an admin; never the
    agent): shared_with lists accounts, or ["*"] for every account; findings=True shares its findings
    and dossier too. Copies already made stay with their cases. Written to the case's audit log.
    """
    from copilot import auth
    _check(case_id)
    if not can_manage(case_id):
        raise CaseError("Only the case owner or an admin can share a case.")
    wanted = sorted({str(u).strip() for u in shared_with or [] if str(u).strip()})
    if EVERYONE in wanted:
        wanted = [EVERYONE]
    known = set(auth.usernames())
    unknown = [u for u in wanted if u != EVERYONE and known and u not in known]
    if unknown:
        raise CaseError(f"No such account: {', '.join(unknown)}.")
    data = _read(case_id)
    old = sharing_of(data)
    access = data["access"] if isinstance(data.get("access"), dict) else {}
    if wanted:
        access.update(shared_with=wanted, share_findings=bool(findings))
    else:
        access.pop("shared_with", None)
        access.pop("share_findings", None)
    data["access"] = access
    _write(case_id, data)
    shown = lambda s: ("everyone" if s[0] == [EVERYONE] else ", ".join(s[0]) or "nobody") + \
        (" (with findings)" if s[0] and s[1] else "")
    _audit(case_id, "case_sharing", f"shared with {shown(old)} -> {shown((wanted, bool(findings)))}")
    return {"shared_with": wanted, "share_findings": bool(findings) and bool(wanted)}


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


def copy_data(source_id: str, target_id: str, findings: bool = False, triage: list = None,
              triage_steps: list = None) -> dict:
    """
    Copies collected data (records, timeline, search index, collections) from one case to
    another on the same evidence; the source may be one shared with the user. findings=True also
    copies its active findings (marked with their origin) and, if the target has none, its latest
    dossier. Outputs, chats and the audit trail stay behind. The copy is written to both cases'
    audit logs, so a case's owner sees who started from it.

    triage (artifact / collection names): copy only the source's triage, i.e. what was collected
    before its first other collection (a benchmark run reusing an earlier run's data must not get
    what that run's agent collected). counts["triage"] lists the triage collections copied.
    triage_steps (the source's collection plan): a triage artifact collected again with its plan's
    parameters, after they changed, is triage too.
    """
    import sqlite3
    from copilot.database import CaseDatabase
    _check(source_id, reuse=True)
    _check(target_id)
    if findings and not can_reuse(source_id, findings=True):
        raise CaseError(f"Case '{source_id}' is shared without its findings: only its collected data can be copied.")
    source_sources, target_sources = _sources(_read(source_id)), _sources(_read(target_id))
    held = collected_sources(source_id)
    for kind, label in (("client", "evidence clients"), ("memory", "memory images")):
        target = target_sources.get(kind)
        other = [s for s in dict.fromkeys([source_sources.get(kind), *held[kind]])
                 if s and target and not _same_source(kind, s, target)]
        if other:
            raise CaseError(f"Cases are on different {label} ({', '.join(other)} vs {target}).")
    src_db = os.path.join(data_dir_for(_case_file(source_id)), "case.db")
    if not os.path.isfile(src_db):
        raise CaseError(f"Case '{source_id}' has no data yet.")
    target = CaseDatabase(data_dir_for(_case_file(target_id)))
    counts = {}
    try:
        target.conn.execute("ATTACH DATABASE ? AS src", (src_db,))
        # Every row (all of them, or the triage's: what was ingested before the first other collection).
        records, params, flows = "SELECT evidence_id FROM src.records", [], None
        if triage is not None:
            cutoff, flows = _triage_part(target.conn, triage, triage_steps)
            if cutoff:
                records, params = records + " WHERE ingested_at < ?", [cutoff]
            counts["triage"] = flows
        wheres = {"records": (f"WHERE evidence_id IN ({records})", params),
                  "timeline": (f"WHERE evidence_id IN ({records})", params),
                  "collections": ("", []) if flows is None else ("WHERE 0", []) if not flows else
                                 ("WHERE flow_id IN (%s)" % ",".join("?" * len(flows)), flows)}
        for table in ("records", "timeline", "collections"):
            where, args = wheres[table]
            before = target.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            target.conn.execute(f"INSERT OR IGNORE INTO {table} SELECT * FROM src.{table} {where}", args)
            counts[table] = target.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] - before
        try:                                   # memory image hashes (databases from before them have none)
            target.conn.execute("INSERT OR IGNORE INTO evidence_files SELECT * FROM src.evidence_files")
        except sqlite3.OperationalError:
            pass
        if target.has_fts:
            try:
                target.conn.execute("INSERT INTO records_fts (evidence_id, text) SELECT s.evidence_id, s.text "
                                    "FROM src.records_fts s WHERE s.evidence_id NOT IN "
                                    f"(SELECT evidence_id FROM records_fts) AND s.evidence_id IN ({records})", params)
            except sqlite3.OperationalError:
                pass
        if findings:
            counts.update(_copy_findings(target.conn, source_id))
        target.conn.commit()
        target.conn.execute("DETACH DATABASE src")
        target.log_query("copy_case_data", f"from case {source_id}: {counts}", counts["records"])
    finally:
        target.conn.close()
    _audit(source_id, "case_reused", f"copied into case {target_id}: {counts}")
    return counts


def _triage_part(conn, triage: list, steps: list = None) -> tuple:
    """
    (cutoff, flow IDs) of the attached source's triage: its collections in order, each triage artifact
    once (and again with its step's parameters, when they changed after the first: `steps`), up to the
    first other collection, whose start (cutoff) ends the triage (None: nothing else was collected).
    Before an agent collects, only the triage puts records into a case.
    """
    from copilot.collection import covers
    remaining, flows = set(triage), []
    redone = {s["artifact"]: s["parameters"] for s in steps or [] if s.get("parameters")}
    for flow_id, artifact, parameters, requested in conn.execute(
            "SELECT flow_id, artifact, parameters, requested_at FROM src.collections ORDER BY requested_at, rowid"):
        if artifact in remaining:
            remaining.discard(artifact)
            flows.append(flow_id)
            continue
        if artifact in redone and covers(parameters, redone.pop(artifact)):
            flows.append(flow_id)
            continue
        return requested, flows
    return None, flows


FINDING_COLUMNS = ["finding_id", "timestamp_utc", "title", "description", "evidence_ids", "confidence",
                   "mitre_technique", "created_at"]


def _copy_findings(conn, source_id: str) -> dict:
    """Active findings and the latest dossier of the attached database `src` (copy_data)."""
    owner = access_of(_read(source_id))[0]
    origin = f"case {source_id}" + (f" ({owner})" if owner else "")
    cols = {r[1] for r in conn.execute("PRAGMA src.table_info(findings)")}
    where = "WHERE COALESCE(status, 'active') = 'active'" if "status" in cols else ""
    keep = "COALESCE(origin, ?)" if "origin" in cols else "?"      # a finding imported twice keeps its first origin
    before = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    conn.execute(f"INSERT OR IGNORE INTO findings ({', '.join(FINDING_COLUMNS)}, status, origin) "
                 f"SELECT {', '.join(FINDING_COLUMNS)}, 'active', {keep} FROM src.findings {where}", (origin,))
    counts = {"findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] - before, "dossier": 0}
    tables = {r[0] for r in conn.execute("SELECT name FROM src.sqlite_master WHERE type = 'table'")}
    has_own = conn.execute("SELECT 1 FROM dossiers LIMIT 1").fetchone()
    if "dossiers" in tables and not has_own:
        row = conn.execute("SELECT text, created_at, actor, findings, steps, tokens FROM src.dossiers "
                           "ORDER BY dossier_id DESC LIMIT 1").fetchone()
        if row:
            by = f" by {row[2]}" if row[2] else ""
            text = (f"Imported from {origin}: written {str(row[1])[:16].replace('T', ' ')} UTC{by}. Check it against "
                    f"this case before relying on it.\n\n{row[0]}")
            conn.execute("INSERT INTO dossiers (created_at, actor, text, findings, steps, tokens) VALUES (?,?,?,?,?,?)",
                         (row[1], row[2], text, row[3], row[4], row[5]))
            counts["dossier"] = 1
    return counts


def legacy_data_hint() -> str:
    """
    Before cases were separated, every case used case_data/case.db. If that file exists
    and the active case has no database yet, tell the investigator how to move it.
    """
    root = os.environ.get("DFIR_DATA_DIR", LEGACY_DATA_ROOT)
    legacy = os.path.join(root, "case.db")
    if session.current_user() is not None:
        return ""   # the hint names server paths: only for a single investigator without sign-in
    case_id = current_id()
    if case_id == LEGACY_ID or os.environ.get("DFIR_CASE_DIR") or not os.path.isfile(legacy):
        return ""
    target = data_dir_for(_case_file(case_id))
    if case_db.get_stats()["total_records"] or case_db.get_collections() or case_db.get_findings(True):
        return ""
    return (f"Found {legacy} from before cases were separated. If it belongs to case '{case_id}', stop the "
            f"copilot and move it (and its outputs folder) into {target}{os.sep}.")


def move_data(yes: bool = False, log=print) -> list:
    """
    Moves each case's data from the old case_data/<id>/ into its own folder (<cases_dir>/<id>/data),
    so a case's settings and data share one folder. Run it with the app and the CLI stopped: open
    databases can't be moved. Data folders without a case folder are left where they are.
    """
    import shutil
    if os.environ.get("DFIR_DATA_DIR") or os.environ.get("DFIR_CASE_DIR"):
        log("DFIR_DATA_DIR or DFIR_CASE_DIR is set: the data is meant to stay where it is. Nothing moved.")
        return []
    moved = []
    names = sorted(os.listdir(LEGACY_DATA_ROOT)) if os.path.isdir(LEGACY_DATA_ROOT) else []
    for name in names:
        old = os.path.join(LEGACY_DATA_ROOT, name)
        if not os.path.isdir(old):
            continue                           # e.g. the legacy root case's own case.db
        case_folder = os.path.join(cases_dir(), name)
        new = os.path.join(case_folder, CASE_DATA_FOLDER)
        if not os.path.isfile(os.path.join(case_folder, "case.yaml")):
            log(f"Skipped {old}: no case folder {case_folder}")
            continue
        if os.path.exists(new):
            log(f"Skipped {old}: {new} already exists (move or merge it by hand)")
            continue
        log(f"{'Moving' if yes else 'Would move'} {old} -> {new}")
        if yes:
            try:
                shutil.move(old, new)
            except OSError as e:
                log(f"  failed ({e}): stop the app and the CLI, then run this again")
                continue
        moved.append(name)
    if moved and not yes:
        log("Run again with --yes to move them (stop the app and the CLI first).")
    elif not moved:
        log("Nothing to move.")
    return moved


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="python -m copilot.cases")
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("move-data", help="move case data from case_data/<id> into cases/<id>/data")
    m.add_argument("--yes", action="store_true", help="really move (default: only show what would move)")
    args = parser.parse_args(argv)
    if args.command == "move-data":
        move_data(args.yes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
