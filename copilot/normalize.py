"""
Turns raw Velociraptor rows into normalized records and timeline events.

Artifact-agnostic on purpose (Windows and Linux, any Velociraptor version):
  - timestamps are found by VALUE (ISO-8601/RFC3339 strings anywhere in the row,
    numeric epoch/FILETIME values in time-named fields), normalized to UTC;
  - every distinct timestamp in a row becomes its own timeline event, labelled
    with the field(s) it came from (e.g. "Created0x10, Modified0x10");
  - entities (user, process, command line, path, hash, IP, event ID) are taken
    from well-known field names at any nesting depth;
  - event type comes from an ordered artifact-name table, not substring guessing.
"""
import fnmatch
import json
import re
from datetime import datetime, timedelta, timezone

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Timestamps outside this window are placeholders (1601/1970 zero dates) or garbage.
MIN_PLAUSIBLE = datetime(1990, 1, 1, tzinfo=timezone.utc)
MAX_FUTURE = timedelta(days=366)

MAX_DEPTH = 5
MAX_LIST_ITEMS = 16

_ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)
# Numeric values are only treated as time when the field name says so.
_TIME_NAME_RE = re.compile(
    r"(?i)(time|date|stamp|created|modified|accessed|changed|written|mtime|atime|ctime|btime|epoch|lastrun)"
)

# (artifact pattern, event type): first match wins.
EVENT_TYPES = [
    # Memory images (Volatility, see memory.py): sources are "Memory.<plugin>".
    ("Memory.strings*", "memory_search"),
    ("Memory.*yarascan*", "memory_search"),
    ("Memory.*netscan*", "network"),
    ("Memory.*netstat*", "network"),
    ("Memory.*sockstat*", "network"),
    ("Memory.*malfind*", "code_injection"),
    ("Memory.*hollowprocesses*", "code_injection"),
    ("Memory.*processghosting*", "code_injection"),
    ("Memory.*suspicious_threads*", "code_injection"),
    ("Memory.*ldrmodules*", "code_injection"),
    ("Memory.*cmdscan*", "command_history"),
    ("Memory.*consoles*", "command_history"),
    ("Memory.linux.bash*", "command_history"),
    ("Memory.*svcscan*", "persistence"),
    ("Memory.*svcdiff*", "persistence"),
    ("Memory.*scheduled_tasks*", "persistence"),
    ("Memory.*userassist*", "user_activity"),
    ("Memory.*amcache*", "execution"),
    ("Memory.*shimcache*", "execution"),
    ("Memory.*.ps*", "process"),
    ("Memory.*cmdline*", "process"),
    ("Memory.*", "memory"),
    ("Windows.EventLogs.RDPAuth*", "authentication"),
    ("Windows.EventLogs.*Logon*", "authentication"),
    ("Windows.EventLogs.Powershell*", "script_execution"),
    ("Windows.EventLogs.*", "event_log"),
    ("Windows.System.Powershell.PSReadline*", "command_history"),
    ("Linux.Sys.BashHistory*", "command_history"),
    ("*Prefetch*", "execution"),
    ("*Amcache*", "execution"),
    ("*Shimcache*", "execution"),
    ("*AppCompatCache*", "execution"),
    ("Windows.Forensics.Bam*", "execution"),
    ("Windows.Forensics.SRUM*", "execution"),
    ("Windows.Registry.UserAssist*", "user_activity"),
    ("Windows.Forensics.Lnk*", "user_activity"),
    ("Windows.Forensics.JumpLists*", "user_activity"),
    ("Windows.Forensics.Shellbags*", "user_activity"),
    ("Windows.Registry.RecentDocs*", "user_activity"),
    ("Windows.Forensics.RecycleBin*", "user_activity"),
    ("Windows.NTFS.*", "filesystem"),
    ("*MFT*", "filesystem"),
    ("*USN*", "filesystem"),
    ("Windows.Persistence.*", "persistence"),
    ("Windows.System.TaskScheduler*", "persistence"),
    ("Windows.System.Services*", "persistence"),
    ("Linux.Sys.Crontab*", "persistence"),
    ("Windows.Sys.StartupItems*", "persistence"),
    ("Linux.Ssh.AuthorizedKeys*", "persistence"),
    ("Windows.Registry.*", "registry"),
    ("Windows.Applications.*", "browser"),
    ("*Browser*", "browser"),
    ("Linux.Syslog.SSHLogin*", "authentication"),
    ("Linux.Sys.LastUserLogin*", "authentication"),
    ("Linux.Forensics.Journal*", "event_log"),
    ("Linux.Syslog.*", "event_log"),
    ("Generic.Client.Info*", "system_info"),
    ("*.Sys.Users*", "system_info"),
]
EVENT_TYPE_NAMES = sorted({t for _, t in EVENT_TYPES} | {"other"})

# Entity -> field names (matched case-insensitively on the last path segment).
ENTITY_FIELDS = {
    "user": ["username", "user", "subjectusername", "targetusername", "accountname", "owner", "name_of_user"],
    "process": ["executable", "exe", "image", "processname", "newprocessname", "binary", "application", "binarypath",
                "imagepath", "servicefilename"],
    "command_line": ["commandline", "cmdline", "command", "line", "scriptblocktext", "arguments"],
    "path": ["ospath", "fullpath", "path", "filename", "targetpath", "sourcefile", "file"],
    "hash": ["sha256", "sha1", "md5", "hash", "filehash"],
    "ip": ["ipaddress", "sourceip", "sourceaddress", "sourcenetworkaddress", "remoteaddress", "clientaddress", "ip"],
    "event_id": ["eventid"],
}
# Volatility column names (memory images).
ENTITY_FIELDS["process"] += ["imagefilename", "process", "comm", "binary (registry)"]
ENTITY_FIELDS["command_line"] += ["args"]
ENTITY_FIELDS["ip"] += ["foreignaddr"]
_ENTITY_LOOKUP = {name: entity for entity, names in ENTITY_FIELDS.items() for name in names}

# Per source, field names that mean something else there: (source pattern, {field: entity or None}).
ENTITY_OVERRIDES = [
    ("Memory.*netscan*", {"owner": "process"}),     # the owning process, not an account
    ("Memory.*netstat*", {"owner": "process"}),
    ("Memory.*filescan*", {"name": "path"}),
]

# Per source, a one-line description built from the row's fields. {Field} is the value ("" if
# missing). [text] is kept only if every field in it has a value; [text|other] says `other`
# instead, so a value Volatility could not read is named as such, not left as an empty label.
# Bump NORMALIZER_VERSION when this changes: stored descriptions are then rebuilt.
DESCRIPTION_TEMPLATES = [
    ("Memory.*.info.*", "memory image {Variable}: {Value}"),
    ("Memory.*pslist*", "process {ImageFileName}[ PID {PID}][ PPID {PPID}]"),
    ("Memory.*psscan*", "process {ImageFileName}[ PID {PID}][ PPID {PPID}] (found by scanning)"),
    ("Memory.*pstree*", "process {ImageFileName}[ PID {PID}][ PPID {PPID}][ {Cmd}]"),
    ("Memory.*psxview*", "process {Name}[ PID {PID}] pslist={pslist} psscan={psscan} thrdscan={thrdscan}"),
    ("Memory.*cmdline*", "{Process}[ PID {PID}]: [{Args}|command line not readable from memory (paged out or exited)]"),
    ("Memory.*netscan*", "{Proto} {LocalAddr}:{LocalPort} -> {ForeignAddr}:{ForeignPort}[ {State}]"
                         "[ owner {Owner} PID {PID}|; owning process not readable]"),
    ("Memory.*netstat*", "{Proto} {LocalAddr}:{LocalPort} -> {ForeignAddr}:{ForeignPort}[ {State}]"
                         "[ owner {Owner} PID {PID}|; owning process not readable]"),
    ("Memory.*malfind*", "possible injected code in {Process}[ PID {PID}][ at {Start VPN}][ ({Protection})]"
                         "[ {Notes}]"),
    ("Memory.*svcscan*", "service {Name}[ ({Display})][ {State}][ {Start}][ PID {PID}][ binary {Binary}]"
                         "[ registry binary {Binary (Registry)}][ dll {Dll}]"),
    ("Memory.*dlllist*", "{Process}[ PID {PID}] loaded {Path}"),
    ("Memory.*handles*", "{Process}[ PID {PID}] handle {Type}[ {Name}]"),
    ("Memory.*filescan*", "file object {Name}"),
    ("Memory.linux.psaux*", "process {COMM}[ PID {PID}][ PPID {PPID}][: {ARGS}]"),
    ("Memory.linux.pslist*", "process {COMM}[ PID {PID}][ PPID {PPID}]"),
    ("Memory.strings*", 'memory image holds "[{Before}]{Match}"[ ({Encoding})][, {Hits}x][ first at {Offset}]'),
    ("Memory.*yarascan*", '[{Process} ]PID {PID} memory holds "{Match}"[ ({Encoding})][, {Hits}x][, rule {Rule}]'),
]
NORMALIZER_VERSION = 4
_FIELD_RE = re.compile(r"\{([^{}]+)\}")

# Fields that make the best one-line description, in order of preference.
DESCRIPTION_FIELDS = ["message", "commandline", "scriptblocktext", "line", "command", "description", "name", "ospath", "fullpath"]


def event_type_for(source: str) -> str:
    artifact = source.split("/", 1)[0].lower()
    for pattern, event_type in EVENT_TYPES:
        if fnmatch.fnmatchcase(artifact, pattern.lower()):
            return event_type
    return "other"


def flatten(row, prefix: str = "", depth: int = 0):
    """Yields (dotted.key, scalar) pairs; lists are expanded as key[i]."""
    if isinstance(row, dict):
        if depth >= MAX_DEPTH:
            return
        for key, value in row.items():
            yield from flatten(value, f"{prefix}.{key}" if prefix else str(key), depth + 1)
    elif isinstance(row, list):
        for i, value in enumerate(row[:MAX_LIST_ITEMS]):
            yield from flatten(value, f"{prefix}[{i}]", depth + 1)
    else:
        yield prefix, row


def _last_segment(key: str) -> str:
    return re.sub(r"\[\d+\]$", "", key.rsplit(".", 1)[-1])


def _plausible(ts: datetime, now: datetime) -> bool:
    return MIN_PLAUSIBLE <= ts <= now + MAX_FUTURE


def _from_number(value: float):
    """Epoch seconds/ms/us/ns or Windows FILETIME, chosen by magnitude."""
    v = abs(value)
    try:
        if 1.16e17 <= v < 1.6e17:      # FILETIME (100ns since 1601): years ~1969-2108
            return FILETIME_EPOCH + timedelta(microseconds=value / 10)
        if 1e8 <= v < 1e10:            # seconds
            return EPOCH + timedelta(seconds=value)
        if 1e11 <= v < 1e13:           # milliseconds
            return EPOCH + timedelta(milliseconds=value)
        if 1e14 <= v < 1e16:           # microseconds
            return EPOCH + timedelta(microseconds=value)
        if 1e17 <= v < 1e19:           # nanoseconds
            return EPOCH + timedelta(microseconds=value / 1000)
    except OverflowError:
        return None
    return None


def parse_timestamp(value, field_name: str = "", now: datetime = None):
    """Returns an aware UTC datetime, or None if the value isn't a plausible timestamp."""
    now = now or datetime.now(timezone.utc)
    ts = None
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        m = _ISO_RE.match(text)
        if m:
            date, clock, frac, tz = m.groups()
            if clock.count(":") == 1:
                clock += ":00"
            frac = (frac or "")[:6].ljust(6, "0")
            tz = "+00:00" if tz in (None, "Z") else (tz if ":" in tz else f"{tz[:3]}:{tz[3:]}")
            try:
                ts = datetime.fromisoformat(f"{date}T{clock}.{frac}{tz}")
            except ValueError:
                return None
        elif text.isdigit() and _TIME_NAME_RE.search(field_name):
            ts = _from_number(int(text))
    elif isinstance(value, (int, float)) and _TIME_NAME_RE.search(field_name):
        ts = _from_number(value)
    if ts is None:
        return None
    ts = ts.astimezone(timezone.utc)
    return ts if _plausible(ts, now) else None


def format_ts(ts: datetime) -> str:
    """Fixed-width UTC ISO-8601, so string order == time order in SQLite."""
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def normalize_bound(value: str):
    """Normalizes a user/LLM supplied time bound to the stored format (None if empty)."""
    if not value:
        return None
    ts = parse_timestamp(value, "time")
    if ts is None:
        raise ValueError(f"Unrecognized timestamp '{value}'. Use ISO 8601, e.g. 2024-01-15T10:00:00Z.")
    return format_ts(ts)


def extract_timestamps(row: dict, now: datetime = None) -> list:
    """
    Returns [(timestamp_utc, "field, field"), ...], one entry per distinct time.
    Underscore fields are Velociraptor bookkeeping (e.g. _ts = collection time) and skipped.
    """
    now = now or datetime.now(timezone.utc)
    found = {}
    for key, value in flatten(row):
        if any(part.startswith("_") for part in key.split(".")):
            continue
        ts = parse_timestamp(value, _last_segment(key), now)
        if ts is not None:
            found.setdefault(format_ts(ts), []).append(key)
    return sorted((ts, ", ".join(fields)) for ts, fields in found.items())


def _for_source(table: list, source: str):
    source = (source or "").split("/", 1)[0].lower()
    return next((value for pattern, value in table if fnmatch.fnmatchcase(source, pattern.lower())), None)


def extract_entities(row: dict, cap: int = 1000, source: str = "") -> dict:
    """Entity values are capped for the database/LLM; pass cap=None for full values (reports)."""
    entities = {}
    overrides = _for_source(ENTITY_OVERRIDES, source) or {}
    for key, value in flatten(row):
        if value in (None, "") or isinstance(value, (bool, dict, list)):
            continue
        field = _last_segment(key).lower()
        entity = overrides[field] if field in overrides else _ENTITY_LOOKUP.get(field)
        if entity and entity not in entities:
            entities[entity] = str(value) if cap is None else str(value)[:cap]
    return entities


# Short fields that say what kind of event a row is; shown before long messages.
KEY_FIELDS = ["LogonType", "Reason", "ServiceName", "TaskName", "Channel"]
# Entities in the order they should appear; path last (often just the log file).
DESCRIPTION_ENTITIES = ["event_id", "user", "ip", "process", "command_line", "hash"]


_OPTIONAL_RE = re.compile(r"\[([^\[\]]*)\]")


def _from_template(template: str, row: dict) -> str:
    def has(name):
        return row.get(name) not in (None, "")

    if not any(has(name) for name in _FIELD_RE.findall(template)):
        return ""

    def optional(m):
        kept, _, otherwise = m.group(1).partition("|")
        return kept if all(has(n) for n in _FIELD_RE.findall(kept)) else otherwise

    text = _OPTIONAL_RE.sub(optional, template)
    text = _FIELD_RE.sub(lambda m: str(row.get(m.group(1))) if has(m.group(1)) else "", text)
    return " ".join(text.split())


def describe(row: dict, entities: dict, limit: int = 500, source: str = "") -> str:  # limit=None: no cap
    """
    One line per record: identifying facts first (event ID, key fields, user, IP...),
    then the message, then the path, so truncated text still says what happened.
    """
    template = _for_source(DESCRIPTION_TEMPLATES, source)
    if template and isinstance(row, dict):
        text = _from_template(template, row)
        if text:
            return text if limit is None else text[:limit]
    fields = {}
    for key, value in flatten(row):
        if value not in (None, "") and not isinstance(value, bool):
            fields.setdefault(_last_segment(key).lower(), str(value))
    primary = next((fields[f] for f in DESCRIPTION_FIELDS if f in fields), "")
    parts = []
    for entity in DESCRIPTION_ENTITIES:
        value = entities.get(entity)
        if value and value not in primary:
            parts.append(f"{entity}={value}")
    for name in KEY_FIELDS:
        value = fields.get(name.lower())
        if value and value not in primary and name != "Channel":
            parts.insert(1 if parts and parts[0].startswith("event_id=") else 0, f"{name}={value}")
    parts.append(primary)
    if entities.get("path") and entities["path"] not in primary:
        parts.append(f"path={entities['path']}")
    text = "; ".join(p for p in parts if p)
    if not text:
        text = json.dumps({k: v for k, v in row.items() if not isinstance(v, (dict, list))}, default=str)
    text = " ".join(text.split())
    return text if limit is None else text[:limit]


# Sources whose timestamps describe the collection, not the evidence.
NO_TIMELINE_SOURCES = ["Generic.Client.Info/BasicInformation"]


def normalize_row(row: dict, source: str, now: datetime = None) -> dict:
    entities = extract_entities(row, source=source)
    on_timeline = not any(fnmatch.fnmatchcase(source, p) for p in NO_TIMELINE_SOURCES)
    return {
        "event_type": event_type_for(source),
        "entities": entities,
        "description": describe(row, entities, source=source),
        "timestamps": extract_timestamps(row, now) if on_timeline else [],
    }
