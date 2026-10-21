"""
Collections the code makes from what was collected, before an investigation (no model involved).

The MFT records of the files touched in the sessions to check (leads.sessions: files with a time in
the session's window in the USN journal, shortcuts, the Recycle Bin, downloads and the user-folder
listing), so leads.timestamp_changes can show a file whose timestamps were set by hand, whichever
file the model would have chosen to look at. Like the triage, it is the investigator's own action
(the investigation they started); collection.collect reuses an identical earlier collection, so
investigating again repeats nothing.
"""
import json
import ntpath

from copilot import collection, leads
from copilot.case_config import case_config
from copilot.database import case_db

MAX_NAMES = 40              # file names in one FileRegex
SESSIONS = 4                # the sessions whose files are checked (leads.sessions_to_check shows the same ones)
# Files every profile has: their timestamps say nothing about an intruder.
_ORDINARY = {"desktop.ini", "thumbs.db", "ntuser.dat", "ntuser.ini", "usrclass.dat", "index.dat"}
_RE2_SPECIAL = set("\\.^$|?*+()[]{}")


def _literal(name: str) -> str:
    """The name as a regular expression that Velociraptor (Go RE2) reads literally (spaces stay as they are)."""
    return "".join("\\" + c if c in _RE2_SPECIAL else c for c in name)


def _path_of(source: str, raw: dict) -> str:
    """The file a record is about, by source."""
    if source.startswith("Windows.Forensics.Lnk"):
        target = (raw.get("LinkTarget") or {}).get("LinkTarget") if isinstance(raw.get("LinkTarget"), dict) else ""
        path = target or ((raw.get("LinkInfo") or {}).get("LocalBasePath") if isinstance(raw.get("LinkInfo"), dict) else "")
    elif source.startswith("Windows.Forensics.RecycleBin"):
        path = raw.get("OriginalFilePath")
    elif source.startswith("Windows.Analysis.EvidenceOfDownload"):
        path = raw.get("DownloadedFilePath")
    elif source.startswith("Windows.Forensics.Usn"):
        path = raw.get("OSPath") or raw.get("Filename")
    elif source.startswith(("Windows.Search.FileFinder", "Generic.Detection.Yara.Glob")):
        path = "" if leads._flag(raw.get("IsDir")) else raw.get("OSPath")
    else:
        path = ""
    return str(path or "").replace("/", "\\").strip()


def touched_files(db=None) -> list:
    """Names of the files the sessions to check touched, as first seen, without repeats or ordinary profile files."""
    db = db or case_db
    ranked = sorted(leads.sessions(db), key=lambda s: s["_rank"])[:SESSIONS]
    ids = [item["evidence_id"] for s in ranked for item in s["same_time_window"]["files"]]
    found = {}
    for start in range(0, len(ids), 500):
        chunk = ids[start:start + 500]
        found.update((r[0], r[1:]) for r in db.conn.execute(
            f"SELECT evidence_id, source, raw_data FROM records WHERE evidence_id IN ({','.join('?' * len(chunk))})", chunk))
    names, seen = [], set()
    for evidence_id in ids:                       # in the order the sessions' windows list them
        source, raw = found.get(evidence_id, ("", None))
        try:
            path = _path_of(source, json.loads(raw or "{}"))
        except (TypeError, ValueError, AttributeError):
            continue
        name = ntpath.basename(path)
        if not name or name.lower() in seen or name.lower() in _ORDINARY or leads._OS_FILES.search(path):
            continue
        seen.add(name.lower())
        names.append(name)
    return names


def before_investigation(emit=None) -> str:
    """
    Runs the checks the case allows (a Velociraptor client is set) and returns a note for the investigation
    ("" if nothing was checked). Failures are reported in the note, never raised.
    """
    emit = emit or (lambda kind, payload: None)
    if case_config.client_id_error:
        return ""
    names = touched_files()[:MAX_NAMES]
    if not names:
        return ""
    emit("tool", f"check: MFT records of {len(names)} files touched in the sessions to check")
    params = {"FileRegex": "(?i)^(" + "|".join(_literal(n) for n in names) + ")$",
              "DateAfter": "", "DateBefore": ""}          # their times are what is checked: no window
    from copilot.agent import status_line
    try:
        summary = collection.collect("Windows.NTFS.MFT", params)
    except collection.CollectionError as e:
        return f"\nThe code could not read the MFT records of the files touched in the sessions to check: {e}\n"
    emit("collection", status_line(summary))
    return (f"\nBefore this turn the code collected the MFT records of {len(names)} files touched in the sessions to "
            f"check ({summary.get('state')}, flow {summary.get('flow_id')}); case_summary's timestamps_set_by_hand "
            f"lists those whose timestamps look set by hand.\n")
