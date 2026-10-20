"""
Leads computed from the collected data without the LLM: who logged on from where (failures and
successes per source address), account and group changes, new services and scheduled tasks, log
clearing, Defender events, downloads and programs in user folders. Every item carries the evidence
IDs to cite. They are starting points for the agent to confirm, not findings.

Reading 100,000 logon records one search at a time cost the agent most of its budget and it still
named the wrong source; grouping them here takes a second.
"""
import ipaddress
import json
import re
from collections import Counter

# Fields the normalizer puts at the start of an event's description (normalize.event_fields).
_FIELD_RE = re.compile(r"(?:^|; )(LogonType|user|domain|ip|workstation|logon_id|by|by_logon_id|server|group|"
                       r"member|member_sid)=([^;]*)")
LOGON_EVENTS = ("4624", "4625", "4648", "1149", "21", "25")
NO_ADDRESS = "(no address)"
ACCOUNT_EVENTS = {"4720": "account created", "4722": "account enabled", "4724": "password reset",
                  "4725": "account disabled", "4726": "account deleted", "4781": "account renamed",
                  "4728": "added to a global group", "4732": "added to a local group",
                  "4756": "added to a universal group"}
SECTION_LIMIT = 15
# Command lines and paths that deserve a look when a service or task runs them.
_USER_WRITABLE = re.compile(r"(?i)\\(users|programdata|temp|tmp|perflogs|recycle)|\\appdata\\|\\downloads\\|\\desktop\\")
_LOLBINS = re.compile(r"(?i)\b(powershell|pwsh|cmd(\.exe)?\s*/c|psexec|rundll32|regsvr32|mshta|wscript|cscript|"
                      r"certutil|bitsadmin|wmic|schtasks)\b")
_VENDOR_TASK = re.compile(r"(?i)^\\microsoft\\")
_EXECUTABLE = re.compile(r"(?i)\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi)$")


def _fields(description: str) -> dict:
    return {k: v.strip() for k, v in _FIELD_RE.findall(description or "")}


# Private (RFC 1918), link-local and unique-local ranges; everything else is reached from outside.
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                                 "fc00::/7", "fe80::/10")]


def _scope(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "local"
    return "internal" if any(address in net for net in _INTERNAL if net.version == address.version) else "external"


def _at(row) -> dict:
    return {"timestamp_utc": row["first_seen"], "evidence_id": row["evidence_id"]}


def _top(counter: Counter, n: int = 3) -> dict:
    return dict(counter.most_common(n))


def logon_sources(db, ip: str = None, account: str = None, start: str = None, end: str = None,
                  limit: int = 20) -> dict:
    """
    Logons per source address: failures (4625), successes (4624), explicit credentials (4648) and RDP
    session events, with the accounts, logon types and workstation names used, the first and last of
    each with evidence IDs, and whether a success came after failures from the same address.
    """
    sql = (f"SELECT evidence_id, event_id, first_seen, description FROM records "
           f"WHERE event_id IN ({','.join('?' * len(LOGON_EVENTS))}) AND first_seen IS NOT NULL")
    params = list(LOGON_EVENTS)
    if ip:                       # the extracted ip column is indexed
        sql, params = sql + " AND ip = ?", params + [ip]
    if start:
        sql, params = sql + " AND first_seen >= ?", params + [start]
    if end:
        sql, params = sql + " AND first_seen <= ?", params + [end]
    seen, sources = set(), {}
    for row in db.conn.execute(sql + " ORDER BY first_seen", params):
        f = _fields(row["description"])
        address = f.get("ip", "")
        if not address or address in ("-", "::", "0.0.0.0"):
            # RDP with Network Level Authentication logs failures without the source address, with the
            # client's workstation name: keep them, grouped by that name.
            if row["event_id"] != "4625" or not f.get("workstation") or ip:
                continue
            address = f"{NO_ADDRESS} {f['workstation']}"
        if ip and address != ip:
            continue
        if account and account.lower() not in (f.get("user") or "").lower():
            continue
        # The same event collected by two artifacts (RDPAuth and EvtxHunter) counts once.
        key = (row["event_id"], row["first_seen"], address, f.get("user"), f.get("logon_id"), f.get("LogonType"))
        if key in seen:
            continue
        seen.add(key)
        scope = "no address recorded" if address.startswith(NO_ADDRESS) else _scope(address)
        s = sources.setdefault(address, {"ip": address, "scope": scope, "failures": 0, "successes": 0,
                                         "explicit_credentials": 0, "rdp_events": 0, "_failed": Counter(),
                                         "_accounts": Counter(), "_types": Counter(), "_workstations": Counter()})
        if f.get("workstation"):
            s["_workstations"][f["workstation"]] += 1
        event = row["event_id"]
        if event == "4625":
            s["failures"] += 1
            s["_failed"][f.get("user") or "?"] += 1
            s.setdefault("first_failure", _at(row))
            s["last_failure"] = _at(row)
        elif event == "4624":
            s["successes"] += 1
            s["_accounts"][f.get("user") or "?"] += 1
            s["_types"][f.get("LogonType") or "?"] += 1
            success = {**_at(row), "user": f.get("user"), "logon_type": f.get("LogonType"),
                       "logon_id": f.get("logon_id")}
            if "first_success" not in s:
                s["first_success"] = success
                s["success_after_failures"] = s["failures"] > 0
            s["last_success"] = success
        elif event == "4648":
            s["explicit_credentials"] += 1
        else:
            s["rdp_events"] += 1

    def order(s):
        # Guessing that worked first, then outside addresses that got in, then the rest by volume.
        return (not s.get("success_after_failures"), s["scope"] not in ("external", "no address recorded"),
                s["successes"] == 0,
                -(s["failures"] + s["successes"]))

    ranked = sorted(sources.values(), key=order)
    out = []
    for s in ranked[:limit]:
        item = {k: v for k, v in s.items() if not k.startswith("_") and v not in (0, None)}
        item["scope"] = s["scope"]
        for name, counter in (("failed_accounts", s["_failed"]), ("accounts", s["_accounts"]),
                              ("logon_types", s["_types"]), ("workstations", s["_workstations"])):
            if counter:
                item[name] = _top(counter)
        out.append(item)
    return {"sources": out, "sources_total": len(sources), "logon_events": len(seen),
            "note": "Logon types: 2 console, 3 network (SMB, credential checks), 10 RDP. A success right after "
                    "failures from the same address is guessing that worked. '(no address) NAME': failed logons "
                    "logged without a source address (RDP with NLA), grouped by the client's workstation name; the "
                    "same name on a successful logon gives their address. Confirm with the cited records."}


def _rows(db, where: str, params=()) -> list:
    return db.conn.execute(f"SELECT evidence_id, source, event_id, first_seen, description, raw_data FROM records "
                           f"WHERE {where} ORDER BY first_seen", params).fetchall()


def _raw(row) -> dict:
    try:
        data = json.loads(row["raw_data"] or "{}")
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def account_changes(db) -> list:
    out, seen = [], set()
    marks = ",".join("?" * len(ACCOUNT_EVENTS))
    for row in _rows(db, f"event_id IN ({marks})", list(ACCOUNT_EVENTS)):
        f = _fields(row["description"])
        key = (row["event_id"], row["first_seen"], f.get("user") or f.get("group"), f.get("member_sid"))
        if key in seen:
            continue
        seen.add(key)
        item = {**_at(row), "event": f"{row['event_id']} {ACCOUNT_EVENTS[row['event_id']]}"}
        for name in ("user", "group", "member", "member_sid", "by", "by_logon_id"):
            if f.get(name):
                item[name] = f[name]
        out.append(item)
    return out


def services(db) -> list:
    out = []
    for row in _rows(db, "event_id IN ('7045', '4697')"):
        raw = _raw(row)
        data = raw.get("EventData") if isinstance(raw.get("EventData"), dict) else {}
        binary = data.get("ImagePath") or data.get("ServiceFileName") or ""
        item = {**_at(row), "service": data.get("ServiceName"), "binary": binary,
                "start": data.get("StartType"), "user": raw.get("Username") or data.get("AccountName")}
        if _USER_WRITABLE.search(binary) or _LOLBINS.search(binary):
            item["look"] = "runs from a user-writable folder or through a scripting/admin tool"
        out.append({k: v for k, v in item.items() if v})
    return out


def tasks(db) -> list:
    out = []
    for row in _rows(db, "source LIKE 'Windows.System.TaskScheduler%' OR event_id IN ('4698', '4702')"):
        raw = _raw(row)
        name = raw.get("TaskName") or ""
        command = " ".join(str(raw.get(k) or "") for k in ("Command", "Arguments")).strip()
        if not command:
            command = (row["description"] or "")[:300]
        if _VENDOR_TASK.match(name) and not _USER_WRITABLE.search(command):
            continue          # the operating system's own tasks
        reasons = [why for pattern, why in ((_USER_WRITABLE, "user-writable path"), (_LOLBINS, "scripting/admin tool"))
                   if pattern.search(command)]
        if not reasons and raw.get("LogonType") != "Password":
            continue
        if raw.get("LogonType") == "Password":
            reasons.append("stored password")
        out.append({**_at(row), "task": name or raw.get("OSPath"), "command": command[:300],
                    "user": raw.get("UserId"), "look": ", ".join(reasons)})
    return out


def log_clearing_and_defender(db) -> list:
    out = []
    for row in _rows(db, "event_id IN ('1102', '104', '1116', '1117', '5001')"):
        raw = _raw(row)
        channel = str(raw.get("Channel") or "")
        meaning = {("1102", "Security"): "Security log cleared", ("104", "System"): "event log cleared",
                   ("1116", "Defender"): "Defender detection", ("1117", "Defender"): "Defender action on a detection",
                   ("5001", "Defender"): "Defender real-time protection disabled"}
        what = next((m for (eid, ch), m in meaning.items() if row["event_id"] == eid and ch.lower() in channel.lower()), None)
        if what:
            out.append({**_at(row), "event": f"{row['event_id']} {what}", "detail": (row["description"] or "")[:200]})
    return out


def downloads(db) -> list:
    """Downloaded files grouped by where they came from (HostUrl, or the archive they were extracted from)."""
    groups = {}
    for row in _rows(db, "source LIKE 'Windows.Analysis.EvidenceOfDownload%'"):
        raw = _raw(row)
        origin = raw.get("HostUrl") or raw.get("ReferrerUrl") or "(no HostUrl or referrer)"
        g = groups.setdefault(origin, {"origin": origin, "files": 0, "first": _at(row), "examples": []})
        g["files"] += 1
        g["last"] = _at(row)
        if len(g["examples"]) < 3:
            g["examples"].append(str(raw.get("DownloadedFilePath") or "")[-120:])
    return sorted(groups.values(), key=lambda g: g["first"]["timestamp_utc"] or "")


def user_folder_programs(db) -> list:
    """Executables Amcache saw in user folders (presence, not execution; the time is an inventory time)."""
    out, seen = [], set()
    for row in _rows(db, "source LIKE 'Windows.Forensics.Amcache%' OR source LIKE 'Windows.System.Amcache%'"):
        raw = _raw(row)
        path = str(raw.get("FullPath") or raw.get("LowerCaseLongPath") or raw.get("Path") or "")
        if not path or not _EXECUTABLE.search(path) or not _USER_WRITABLE.search(path):
            continue
        if "\\appdata\\local\\microsoft\\" in path.lower() or path.lower() in seen:
            continue
        seen.add(path.lower())
        out.append({**_at(row), "path": path, "sha1": raw.get("SHA1") or raw.get("Hash") or raw.get("FileId")})
    return out


# Names that only a host serving web pages has (server programs, services, web roots). Generic: no case facts.
WEB_SERVER_SIGNS = ("httpd.exe", "w3wp.exe", "nginx.exe", "php-cgi", "tomcat", "W3SVC", "inetpub", "htdocs",
                    "wwwroot", "apache2", "lighttpd")


def web_server(db) -> list:
    """
    Signs that the host serves web pages (from the search index only, so it stays fast on large cases).
    When there are any, its access logs are the main record of an attack on it: read them.
    """
    if not getattr(db, "has_fts", False):
        return []
    out = []
    for sign in WEB_SERVER_SIGNS:
        rows = db.conn.execute("SELECT r.evidence_id, r.source, r.description FROM records_fts f "
                               "JOIN records r ON r.evidence_id = f.evidence_id WHERE records_fts MATCH ? LIMIT 50",
                               ('"' + sign + '"',)).fetchall()
        if rows:
            out.append({"sign": sign, "records": len(rows) if len(rows) < 50 else "50+", "evidence_id": rows[0][0],
                        "source": rows[0][1], "example": str(rows[0][2] or "")[:160]})
    return out


# Leads per database state: case_summary opens every question, and the data rarely changed since.
_CACHE = {}


def leads(db, sources_limit: int = 8) -> dict:
    """Every section, capped; an empty section only means nothing of that kind was collected or found."""
    state = tuple(db.conn.execute("SELECT COUNT(*), MAX(rowid) FROM records").fetchone())
    key = (getattr(db, "db_path", None) or id(db.conn), sources_limit)
    cached = _CACHE.get(key)
    if cached and cached[0] == state:
        return cached[1]
    out = _compute(db, sources_limit)
    _CACHE[key] = (state, out)
    return out


def _compute(db, sources_limit: int) -> dict:
    def capped(items):
        return items[:SECTION_LIMIT] + ([f"... {len(items) - SECTION_LIMIT} more"] if len(items) > SECTION_LIMIT else [])

    logons = logon_sources(db, limit=sources_limit)
    out = {"logon_sources": logons["sources"],
           "account_and_group_changes": capped(account_changes(db)),
           "services_installed": capped(services(db)),
           "scheduled_tasks_to_check": capped(tasks(db)),
           "log_clearing_and_defender": capped(log_clearing_and_defender(db)),
           "downloads_by_origin": capped(downloads(db)),
           "programs_in_user_folders": capped(user_folder_programs(db)),
           "web_server_signs": web_server(db)}
    out = {k: v for k, v in out.items() if v}
    out["about"] = ("Computed from the collected data without the model: starting points to confirm with the cited "
                    "records, not findings. An absent section means nothing of that kind was collected; "
                    "logon_summary has every logon source.")
    return out
