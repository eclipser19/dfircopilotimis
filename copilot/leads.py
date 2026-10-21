"""
Leads computed from the collected data without the LLM: who logged on from where (failures and
successes per source address), account and group changes, new services and scheduled tasks, log
clearing, Defender events, downloads, programs in user folders, files whose content is not what
their name says, what users searched for or watched on the web, the interactive sessions and what
happened in each, autostart entries that point into user folders, and files whose timestamps look
set by hand. Every item carries the evidence IDs to cite. They are starting points for the agent to confirm, not findings.

Reading 100,000 logon records one search at a time cost the agent most of its budget and it still
named the wrong source; grouping them here takes a second.
"""
import fnmatch
import ipaddress
import json
import re
from collections import Counter
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from copilot import file_types
from copilot.normalize import format_ts, parse_timestamp

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
WEB_LIMIT = 40          # search words are short and each can matter
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


def renamed_content(db) -> list:
    """
    Files whose first bytes say another type than their extension, or that have no extension (the
    triage's content scan: Generic.Detection.Yara.Glob with YaraRule "@file_types"). A mismatch is a
    reason to look, not proof of hiding: some programs use a common format under their own extension.
    """
    out, seen = [], set()
    for row in _rows(db, "source LIKE 'Generic.Detection.Yara.Glob%'"):
        raw = _raw(row)
        path, rule = str(raw.get("OSPath") or ""), str(raw.get("Rule") or "")
        if not rule.startswith(file_types.RULE_PREFIX) or path.lower() in seen:
            continue
        seen.add(path.lower())
        wrong = file_types.mismatch(path, rule)
        if wrong:
            out.append({**_at(row), "path": path, **wrong, "size": raw.get("Size")})
    return out


# Search pages: (engine, host regex, path regex, parameter holding the words). Generic: no case facts.
SEARCH_PAGES = [
    ("Google", r"(^|\.)google\.[a-z.]+$", r"^/(search|webhp)?$", "q"),
    ("Bing", r"(^|\.)bing\.com$", r"^/(search)?$", "q"),
    ("DuckDuckGo", r"(^|\.)duckduckgo\.com$", r"^/(html/?)?$", "q"),
    ("Yahoo", r"(^|\.)search\.yahoo\.", r"^/search", "p"),
    ("Yandex", r"(^|\.)yandex\.", r"^/search", "text"),
    ("Baidu", r"(^|\.)baidu\.com$", r"^/s$", "wd"),
    ("Ecosia", r"(^|\.)ecosia\.org$", r"^/search", "q"),
    ("Brave", r"(^|\.)search\.brave\.com$", r"^/search", "q"),
    ("Startpage", r"(^|\.)startpage\.com$", r"search", "query"),
    ("Ask", r"(^|\.)ask\.com$", r"^/web", "q"),
    ("YouTube", r"(^|\.)youtube\.com$", r"^/results$", "search_query"),
    ("Amazon", r"(^|\.)amazon\.", r"^/s$", "k"),
    ("eBay", r"(^|\.)ebay\.", r"^/sch/", "_nkw"),
    ("Wikipedia", r"(^|\.)wikipedia\.org$", r"^/w/index\.php$", "search"),
]
# Any other site's search page: a path with "search" in it and one of these parameters.
SEARCH_PARAMETERS = ("q", "query", "search_query", "search", "keywords", "term", "text")
_URL_FIELDS = ("visited_url", "url_visited", "url", "URL", "Url")


def _browser(source: str) -> str:
    parts = source.split("/")[0].split(".")
    return parts[2] if len(parts) > 3 and parts[1] == "Applications" else parts[0]


def _search_words(url: str) -> tuple:
    """(engine, words) when the URL is a search results page, else None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host, path, query = (parts.hostname or "").lower(), parts.path or "/", parse_qs(parts.query)
    for engine, host_re, path_re, param in SEARCH_PAGES:
        if re.search(host_re, host):
            words = (query.get(param) or [""])[0].strip()
            return (engine, words) if words and re.search(path_re, path) else None
    if "search" in path.lower():
        words = next((query[p][0].strip() for p in SEARCH_PARAMETERS if (query.get(p) or [""])[0].strip()), "")
        if words:
            return host, words
    return None


def web_activity(db) -> dict:
    """
    What users searched for (the words decoded from search pages' URLs, so odd spellings show as typed) and
    which YouTube videos they opened, per user and browser, from the collected browser history.
    """
    searches, videos = {}, {}
    for row in _rows(db, "source LIKE 'Windows.Applications.%' OR source LIKE '%History%'"):
        raw = _raw(row)
        url = next((str(raw[f]) for f in _URL_FIELDS if raw.get(f)), "")
        if not url:
            continue
        who = {"user": raw.get("User") or raw.get("Username") or "", "browser": _browser(row["source"])}
        found = _search_words(url)
        if found:
            key = (who["user"], who["browser"], found[1].lower())
            item = searches.setdefault(key, {"words": found[1], "engine": found[0], **who, **_at(row), "visits": 0})
            item["visits"] += 1
            continue
        parts = urlsplit(url)
        video = (parse_qs(parts.query).get("v") or [""])[0]
        if video and re.search(r"(^|\.)youtube\.com$", (parts.hostname or "").lower()) and parts.path == "/watch":
            title = re.sub(r"\s*-\s*YouTube$", "", str(raw.get("title") or "")).strip()
            item = videos.setdefault((who["user"], video), {"title": title, "video": video, **who, **_at(row)})
            item["title"] = item["title"] or title
    by_time = lambda items: sorted(items, key=lambda i: i["timestamp_utc"] or "")
    return {"searches": by_time(searches.values()), "videos": by_time(videos.values())}


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


# ---------------------------------------------------------------- sessions and what happened in them
INTERACTIVE = {"2": "console", "7": "unlock or reconnect", "10": "RDP", "11": "cached console"}
LOGOFF_EVENTS = ("4634", "4647")
# Events that name the session they ran in (SubjectLogonId): tied to a session by its logon ID.
IN_SESSION_EVENTS = {"4688": "process created", "4698": "task created", "4702": "task changed",
                     "4697": "service installed", "5140": "share accessed", "1102": "Security log cleared",
                     **ACCOUNT_EVENTS}
FOLLOW_HOURS = 8           # a session without a recorded logoff is followed this long, or to its user's next logon
SAME_SESSION_SECONDS = 5   # RDP and admin logons write two 4624s (a second, elevated token): one session
# Records found by time alone (SQL LIKE on the source), and for programs, the fields that are run times.
WINDOW_SOURCES = {
    "programs_run": ("%Prefetch%", "Windows.Forensics.Bam%", "Windows.Registry.UserAssist%"),
    "persistence": ("Windows.System.TaskScheduler%", "Windows.Sys.StartupItems%"),
    "files": ("Windows.Forensics.Usn%", "Windows.Forensics.Lnk%", "Windows.Forensics.RecycleBin%",
              "Windows.Analysis.EvidenceOfDownload%", "Windows.Search.FileFinder%", "Windows.NTFS.MFT%",
              "Generic.Detection.Yara.Glob%"),
}
RUN_TIME_FIELDS = {"event_time", "bam_time", "lastexecution", "lastexecutionts"}
PERSISTENCE_EVENTS = ("7045",)
_SCOPE_RANK = {"external": 0, "no address recorded": 0, "unknown": 1, "internal": 2, "local": 3}


def _key(value) -> str:
    """Logon IDs are logged in hex (0x5108c6) or decimal (5310854) depending on the source: one form."""
    text = str(value or "").strip().lower()
    try:
        return str(int(text, 16) if text.startswith("0x") else int(text))
    except ValueError:
        return text


def _when(text: str):
    return parse_timestamp(text) if text else None


def _logons(db) -> list:
    """Interactive logons (4624 of the types in INTERACTIVE), the two of one RDP or admin logon merged."""
    found, seen = [], set()
    for row in _rows(db, "event_id = '4624'"):
        f = _fields(row["description"])
        if f.get("LogonType") not in INTERACTIVE:
            continue
        user, ip = f.get("user") or "?", f.get("ip") or ""
        ip = "" if ip in ("-", "::", "0.0.0.0", "::1", "127.0.0.1") else ip
        if (row["first_seen"], user, ip, f.get("logon_id")) in seen:
            continue                      # the same event collected by two artifacts
        seen.add((row["first_seen"], user, ip, f.get("logon_id")))
        start = _when(row["first_seen"])
        twin = next((s for s in reversed(found[-20:]) if s["user"] == user and s["ip"] == ip
                     and abs((start - s["_start"]).total_seconds()) <= SAME_SESSION_SECONDS), None)
        if twin:
            twin["logon_ids"].add(_key(f.get("logon_id")))
            twin["logon_types"].add(INTERACTIVE[f["LogonType"]])
            continue
        found.append({"user": user, "ip": ip or "(local)", "scope": _scope(ip) if ip else "local",
                      "logon_types": {INTERACTIVE[f["LogonType"]]}, "logon_ids": {_key(f.get("logon_id"))} - {""},
                      "logon": _at(row), "_start": start})
    return found


def _ends(db, found: list):
    """Each session's end: its logoff (4634/4647 of one of its logon IDs), else its user's next logon or
    FOLLOW_HOURS later."""
    logoffs = {}
    for row in _rows(db, f"event_id IN {LOGOFF_EVENTS}"):
        k = _key(_fields(row["description"]).get("logon_id"))
        if k:
            logoffs.setdefault(k, []).append(row)
    for i, s in enumerate(found):
        ends = [r for k in s["logon_ids"] for r in logoffs.get(k, []) if _when(r["first_seen"]) >= s["_start"]]
        if ends:
            last = max(ends, key=lambda r: r["first_seen"])
            s["logoff"], s["_end"] = _at(last), _when(last["first_seen"])
            continue
        later = [o["_start"] for o in found[i + 1:] if o["user"] == s["user"]]
        s["_end"] = min(later + [s["_start"] + timedelta(hours=FOLLOW_HOURS)])
        s["logoff"] = f"none recorded: followed until {format_ts(s['_end'])}"


def _item(row, text: str = None, field: str = None) -> dict:
    item = {"timestamp_utc": row["timestamp_utc"] if "timestamp_utc" in row.keys() else row["first_seen"],
            "evidence_id": row["evidence_id"], "what": (text or row["description"] or "")[:160]}
    if field:
        item["time_field"] = field
    return item


def _in_window(db, start: str, end: str) -> dict:
    """Programs run, persistence and files with a time in [start, end], one entry per record."""
    out = {kind: [] for kind in WINDOW_SOURCES}
    likes = [(kind, pattern) for kind, patterns in WINDOW_SOURCES.items() for pattern in patterns]
    where = " OR ".join("r.source LIKE ?" for _ in likes)
    rows = db.conn.execute(
        f"SELECT t.timestamp_utc, t.timestamp_desc, r.evidence_id, r.source, r.event_id, r.description "
        f"FROM timeline t JOIN records r ON r.evidence_id = t.evidence_id "
        f"WHERE t.timestamp_utc >= ? AND t.timestamp_utc <= ? AND ({where} OR r.event_id IN {PERSISTENCE_EVENTS + ('',)}) "
        f"ORDER BY t.timestamp_utc", [start, end, *[p for _, p in likes]]).fetchall()
    seen = set()
    for row in rows:
        if row["evidence_id"] in seen:
            continue
        kind = "persistence" if row["event_id"] in PERSISTENCE_EVENTS else next(
            (k for k, p in likes if fnmatch.fnmatchcase(row["source"], p.replace("%", "*"))), None)
        if kind is None:
            continue
        field = str(row["timestamp_desc"] or "")
        if kind == "programs_run" and field.split(".")[-1].lower() not in RUN_TIME_FIELDS:
            continue                      # a Prefetch file's own times are not run times
        seen.add(row["evidence_id"])
        out[kind].append(_item(row, field=field))
    return out


def sessions(db, everything: bool = False, keep=None, limit: int = 30) -> list:
    """
    Interactive sessions (console, RDP, unlock) and what happened in each, oldest first. `by_logon_id`:
    events that name the session's logon ID (proof it was this session). `same_time_window`: programs run,
    persistence and files with a time between the logon and the logoff, which only says when, not who.
    Sessions from outside addresses come first; local sessions only when there are no others, unless
    `everything`. `keep(session)` filters before the (costlier) window queries, which run for the `limit`
    most telling sessions: outside addresses, then the most events with their logon ID.
    """
    found = _logons(db)
    if not found:
        return []
    _ends(db, found)
    by_id = {}
    marks = ",".join("?" * len(IN_SESSION_EVENTS))
    for row in _rows(db, f"event_id IN ({marks})", list(IN_SESSION_EVENTS)):
        k = _key(_fields(row["description"]).get("by_logon_id"))
        if k:
            by_id.setdefault(k, []).append(row)
    remote = [s for s in found if s["scope"] != "local"]
    chosen = [s for s in (found if everything or not remote else remote) if keep is None or keep(s)]
    for s in chosen:
        s["_joined"] = sorted({r["evidence_id"]: r for k in s["logon_ids"] for r in by_id.get(k, [])}.values(),
                              key=lambda r: r["first_seen"])
    chosen = sorted(chosen, key=lambda s: (_SCOPE_RANK.get(s["scope"], 1), -len(s["_joined"])))[:limit]
    out = []
    for s in sorted(chosen, key=lambda s: s["logon"]["timestamp_utc"]):
        start, end = s["logon"]["timestamp_utc"], format_ts(s["_end"])
        joined = s["_joined"]
        item = {k: v for k, v in s.items() if not k.startswith("_")}
        item["logon_types"], item["logon_ids"] = sorted(s["logon_types"]), sorted(s["logon_ids"])
        item["by_logon_id"] = [_item(r, f"{r['event_id']} {IN_SESSION_EVENTS.get(r['event_id'], '')}: "
                                        f"{r['description']}") for r in joined]
        item["same_time_window"] = _in_window(db, start, end)
        item["_rank"] = (_SCOPE_RANK.get(s["scope"], 1), -(len(joined) + sum(map(len, item["same_time_window"].values()))))
        out.append(item)
    return out


def _compact(session: dict, examples: int = 3) -> dict:
    """A session as case_summary shows it: counts and the first few of each kind."""
    short = {k: v for k, v in session.items() if k not in ("by_logon_id", "same_time_window", "_rank")}
    if session["by_logon_id"]:
        short["by_logon_id"] = {"count": len(session["by_logon_id"]), "first": session["by_logon_id"][:examples]}
    window = {kind: {"count": len(items), "first": items[:examples]}
              for kind, items in session["same_time_window"].items() if items}
    if window:
        short["same_time_window"] = window
    return short


def sessions_to_check(db, limit: int = 4) -> list:
    """The sessions most worth a look (outside addresses, most activity), oldest first, compact."""
    ranked = sorted(sessions(db), key=lambda s: s["_rank"])[:limit]
    return [_compact(s) for s in sorted(ranked, key=lambda s: s["logon"]["timestamp_utc"])]


# ---------------------------------------------------------------- autostart entries
_OS_AUTOSTART = re.compile(r"(?i)^\"?[a-z]:\\(windows|program files( \(x86\))?)\\")


def autostart(db) -> list:
    """Run keys and Startup folder entries (Windows.Sys.StartupItems) that start something from a user-writable
    folder or through a scripting or admin tool: what the operating system and installed programs don't do."""
    out = []
    for row in _rows(db, "source LIKE 'Windows.Sys.StartupItems%'"):
        raw = _raw(row)
        command = str(raw.get("Details") or "")
        target = command if isinstance(raw.get("Details"), str) else ""
        where = str(raw.get("OSPath") or "")
        reasons = [why for pattern, why in ((_USER_WRITABLE, "user-writable path"), (_LOLBINS, "scripting/admin tool"))
                   if pattern.search(target) or (pattern is _USER_WRITABLE and "\\startup\\" in where.lower())]
        if not reasons or (_OS_AUTOSTART.search(target) and not _LOLBINS.search(target)):
            continue
        if "\\appdata\\local\\microsoft\\" in target.lower() and not _LOLBINS.search(target):
            continue                      # per-user Microsoft programs (OneDrive, Teams) install there
        out.append({**_at(row), "name": raw.get("Name"), "starts": target[:300] or where[:300], "entry": where[:300],
                    "enabled": raw.get("Enabled"), "look": ", ".join(reasons)})
    return out


# ---------------------------------------------------------------- timestamps set by hand
_OS_FILES = re.compile(r"(?i)^(\\\\[.?]\\)?[a-z]:\\(windows|\$extend|system volume information|"
                       r"programdata\\microsoft\\windows defender)\\")


def _flag(value) -> bool:
    return value is True or str(value).lower() == "true"


def _same_file(path: str) -> str:
    """One key for a path as the MFT (\\\\.\\C:\\...) and the USN journal (C:\\...) write it."""
    return re.sub(r"^\\\\[.?]\\", "", path).lower()


def timestamp_changes(db) -> list:
    """
    Files whose $STANDARD_INFORMATION times (which programs can set) look set by hand, from collected MFT
    records: earlier than the $FILE_NAME times (SI_Lt_FN) and/or whole seconds (USecZeros); and USN records
    of a timestamp or attribute change (BASIC_INFO_CHANGE) without a data change. Operating-system folders
    are left out. Candidates: a moved file can show SI_Lt_FN and a file extracted from an archive USecZeros;
    both together, or with a matching USN change, are the strong ones.
    """
    found = {}
    for row in _rows(db, "source LIKE 'Windows.NTFS.MFT%'"):
        raw = _raw(row)
        path = str(raw.get("OSPath") or raw.get("FullPath") or "")
        if not path or _flag(raw.get("IsDir")) or _OS_FILES.search(path):
            continue
        signs = [name for name, key in (("$SI earlier than $FN", "SI_Lt_FN"), ("whole-second $SI times", "USecZeros"))
                 if _flag(raw.get(key))]
        if not signs:
            continue
        changed = raw.get("LastRecordChange0x10")
        when = format_ts(parse_timestamp(changed)) if changed and parse_timestamp(changed) else row["first_seen"]
        found.setdefault(_same_file(path), {"timestamp_utc": when, "time_field": "LastRecordChange0x10 (entry changed)",
                                        "evidence_id": row["evidence_id"], "path": path, "signs": signs,
                                        "si_created": raw.get("Created0x10"), "fn_created": raw.get("Created0x30"),
                                        "si_modified": raw.get("LastModified0x10"),
                                        "fn_modified": raw.get("LastModified0x30")})
    for row in _rows(db, "source LIKE 'Windows.Forensics.Usn%'"):
        raw = _raw(row)
        reason = " ".join(raw.get("Reason") or []) if isinstance(raw.get("Reason"), list) else str(raw.get("Reason") or "")
        path = str(raw.get("OSPath") or raw.get("FullPath") or raw.get("Filename") or "")
        if "BASIC_INFO_CHANGE" not in reason or "DATA_" in reason or not path or _OS_FILES.search(path):
            continue
        item = found.setdefault(_same_file(path), {**_at(row), "path": path, "signs": []})
        if "USN BASIC_INFO_CHANGE without a data change" not in item["signs"]:
            item["signs"].append("USN BASIC_INFO_CHANGE without a data change")
            item.setdefault("usn_evidence_id", row["evidence_id"])
    return sorted(found.values(), key=lambda i: (-len(i["signs"]), i["timestamp_utc"] or ""))


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
    def capped(items, limit=SECTION_LIMIT):
        return items[:limit] + ([f"... {len(items) - limit} more"] if len(items) > limit else [])

    logons = logon_sources(db, limit=sources_limit)
    web = web_activity(db)
    out = {"logon_sources": logons["sources"],
           "account_and_group_changes": capped(account_changes(db)),
           "services_installed": capped(services(db)),
           "scheduled_tasks_to_check": capped(tasks(db)),
           "log_clearing_and_defender": capped(log_clearing_and_defender(db)),
           "downloads_by_origin": capped(downloads(db)),
           "programs_in_user_folders": capped(user_folder_programs(db)),
           "files_whose_content_is_not_their_name": capped(renamed_content(db)),
           "web_searches": capped(web["searches"], WEB_LIMIT),
           "youtube_videos_opened": capped(web["videos"], WEB_LIMIT),
           "sessions_to_check": sessions_to_check(db),
           "autostart_entries_to_check": capped(autostart(db)),
           "timestamps_set_by_hand": capped(timestamp_changes(db), 10),
           "web_server_signs": web_server(db)}
    out = {k: v for k, v in out.items() if v}
    out["about"] = ("Computed from the collected data without the model: starting points to confirm with the cited "
                    "records, not findings. An absent section means nothing of that kind was collected; "
                    "logon_summary has every logon source.")
    return out
