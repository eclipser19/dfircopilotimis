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
_ENTITY_LOOKUP = {name: entity for entity, names in ENTITY_FIELDS.items() for name in names}

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


def extract_entities(row: dict) -> dict:
    entities = {}
    for key, value in flatten(row):
        if value in (None, "") or isinstance(value, (bool, dict, list)):
            continue
        entity = _ENTITY_LOOKUP.get(_last_segment(key).lower())
        if entity and entity not in entities:
            entities[entity] = str(value)[:1000]
    return entities


# Short fields that say what kind of event a row is; shown before long messages.
KEY_FIELDS = ["LogonType", "Reason", "ServiceName", "TaskName", "Channel"]
# Entities in the order they should appear; path last (often just the log file).
DESCRIPTION_ENTITIES = ["event_id", "user", "ip", "process", "command_line", "hash"]


def describe(row: dict, entities: dict, limit: int = 500) -> str:
    """
    One line per record: identifying facts first (event ID, key fields, user, IP...),
    then the message, then the path, so truncated text still says what happened.
    """
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
    return text[:limit]


# Sources whose timestamps describe the collection, not the evidence.
NO_TIMELINE_SOURCES = ["Generic.Client.Info/BasicInformation"]


def normalize_row(row: dict, source: str, now: datetime = None) -> dict:
    entities = extract_entities(row)
    on_timeline = not any(fnmatch.fnmatchcase(source, p) for p in NO_TIMELINE_SOURCES)
    return {
        "event_type": event_type_for(source),
        "entities": entities,
        "description": describe(row, entities),
        "timestamps": extract_timestamps(row, now) if on_timeline else [],
    }
