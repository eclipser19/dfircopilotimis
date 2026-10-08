import json
import re
from typing import List, Optional
from langchain_core.tools import tool
from copilot import collection
from copilot.collection import CollectionError
from copilot.vql_client import get_vql
from copilot.database import case_db
from copilot.case_config import case_config
from copilot.normalize import EVENT_TYPE_NAMES


def _dump(obj, **_) -> str:
    """Compact JSON for tool output: every character here is paid for in tokens."""
    return json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)


# Extracted fields are already folded into each row's description; repeating them
# as separate keys doubled the size of every result.
_SLIM_DROP = {"hostname", "client_id", "user", "process", "command_line", "path", "hash", "ip", "event_id"}
PAGE_EVENTS = 50
PAGE_RECORDS = 30
DETAIL_VALUE_CHARS = 1000
DETAIL_TOTAL_CHARS = 6000


def _slim(rows: list) -> list:
    return [{k: v for k, v in row.items() if k not in _SLIM_DROP} for row in rows]


def _cap_values(obj):
    if isinstance(obj, dict):
        return {k: _cap_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_cap_values(v) for v in obj[:50]]
    if isinstance(obj, str) and len(obj) > DETAIL_VALUE_CHARS:
        return obj[:DETAIL_VALUE_CHARS] + f"...[{len(obj) - DETAIL_VALUE_CHARS} more chars]"
    return obj


def safe_json_truncate(res_dict: dict, max_records: int = 50) -> str:
    """Safely truncates the results to avoid blowing up the LLM context."""
    results = res_dict.get("results", [])
    log = res_dict.get("log", "")

    output = ""
    if res_dict.get("error"):
        output += f"--- VELOCIRAPTOR CALL FAILED ---\n{res_dict['error']}\n\n"
    if log and log.strip():
        output += f"--- VELOCIRAPTOR LOG / ERRORS ---\n{log.strip()}\n\n"

    truncated = results[:max_records]
    output += _dump(truncated)

    if len(results) > max_records:
        output += f"\n\n... [System Note: Truncated {len(results) - max_records} records. Try narrowing the timeframe or parameters.]"

    return output


def _re2_escape(text: str) -> str:
    """Escape only RE2 metacharacters (Python's re.escape emits escapes RE2 rejects)."""
    return re.sub(r"([\\.+*?()|\[\]{}^$])", r"\\\1", text)


# ========================================================================
# VELOCIRAPTOR COLLECTION TOOLS
# ========================================================================

@tool
def search_clients() -> str:
    """
    Lists clients enrolled in Velociraptor (including dead-disk virtual clients).
    Only useful for setup: collections always run on the case's configured client.
    """
    res = get_vql().run_vql("SELECT client_id, os_info.hostname AS hostname, os_info.system AS os FROM clients()")
    return safe_json_truncate(res)


@tool
def collect_artifact(artifact_name: str, parameters: Optional[dict] = None) -> str:
    """
    TARGETED follow-up collection from the case's disk image, stored in the case database.
    The case's standard triage artifacts are already collected: analyze those first and
    only collect more to test a specific lead. The case time window is applied to the
    artifact's date filters automatically, and results are capped at a row limit.
    Heavy artifacts (MFT, USN journal, EvtxHunter, file searches) require a filter
    parameter (e.g. a filename/path regex or event IDs) or a DateAfter/DateBefore window
    of at most 60 minutes (recorded host time). The investigator may be asked
    to approve the collection. If it is still running, it returns state RUNNING and a
    flow_id for `check_collection`.
    Args:
        artifact_name: The artifact name (e.g., 'Windows.NTFS.MFT').
        parameters: Artifact parameters (e.g., {'FileRegex': 'updater'}). Use the artifact's own
            names from `describe_artifact`; unknown names are refused.
    """
    try:
        return _dump(collection.collect(artifact_name, parameters, requested_by="agent"))
    except CollectionError as e:
        return f"Collection not started or failed: {e}"


@tool
def analyze_memory(plugin: str, pid: Optional[List[int]] = None, contains: Optional[str] = None,
                   key: Optional[str] = None, recurse: Optional[bool] = None, text: Optional[str] = None,
                   rules: Optional[str] = None) -> str:
    """
    Runs a Volatility 3 plugin on the case's MEMORY IMAGE and stores its rows in the case database
    (source "Memory.<plugin>"), next to the disk evidence: query them with query_timeline,
    search_iocs, pivot_entity like any other evidence. Memory shows what was RUNNING at capture
    time: processes (also hidden/exited), command lines, network connections (also closed ones),
    injected code. The memory triage may already have run: check list_collections first.
    Useful plugins: windows.pslist, windows.psscan (hidden/exited processes), windows.pstree,
    windows.cmdline, windows.netscan (connections, C2), windows.malfind (injection),
    windows.dlllist, windows.handles, windows.svcscan, windows.filescan, windows.registry.printkey,
    windows.consoles/cmdscan (typed commands). All: list_memory_plugins.
    SEARCHING memory for an IP, domain, URL or file name that the collected data doesn't explain:
    plugin 'strings' with text (the whole image file, freed memory too, with the surrounding text,
    e.g. the full URL; fast) and 'windows.memsearch' with text (WHICH PROCESS holds it, e.g. the
    owner of a C2 address netscan could not read). windows.memsearch with rules scans with a
    YARA rule file from the server (list_memory_plugins shows them).
    Heavy plugins (dlllist, handles, filescan, envars, printkey...) need pid, contains or key.
    The investigator may be asked to approve. A run can take minutes.
    Args:
        plugin: Plugin name, e.g. 'windows.netscan'.
        pid: Only these process IDs, e.g. [3644] (plugins that take pid).
        contains: Only rows containing this text in any column (case-insensitive), e.g. 'updater.exe'.
        key: Registry key for windows.registry.printkey, e.g. 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'.
        recurse: With key: include subkeys.
        text: For strings / windows.memsearch: the text to find (4+ characters, case-insensitive,
            ASCII and UTF-16), e.g. '10.20.30.40' or 'evil-domain.example'.
        rules: For windows.memsearch: a rule file name from the server's YARA folder.
    """
    from copilot import memory
    options = {"pid": pid, "contains": contains, "key": key, "recurse": recurse, "text": text, "rules": rules}
    try:
        return _dump(memory.run(plugin, options, requested_by="agent"))
    except memory.MemoryAnalysisError as e:
        return f"Memory analysis not run: {e}"


@tool
def list_memory_plugins() -> str:
    """Lists the plugins analyze_memory may run, what each shows, its options, and the YARA rule files."""
    from copilot import memory
    return _dump(memory.plugin_list())


@tool
def check_collection(flow_id: str) -> str:
    """
    Checks a collection started earlier. If it has finished, its results are ingested
    into the case database. Use for collections that `collect_artifact` reported as RUNNING.
    Args:
        flow_id: The flow ID returned by `collect_artifact` (e.g., 'F.CN3ABC...').
    """
    if flow_id.startswith("MEM."):        # memory analyses finish before their tool call returns
        return _dump(case_db.get_collection(flow_id) or {"error": f"No memory analysis {flow_id}."})
    try:
        return _dump(collection.check(flow_id))
    except CollectionError as e:
        return f"Could not check collection: {e}"


@tool
def list_collections() -> str:
    """Lists every collection started in this case, with its state and rows ingested."""
    rows = case_db.get_collections()
    if not rows:
        return "No collections have been started in this case yet."
    return _dump(rows)


@tool
def list_artifacts(keyword: str) -> str:
    """
    Finds artifacts this case is allowed to collect whose name matches a keyword
    (case-insensitive, plain text, e.g. 'evtx', 'prefetch', 'registry').
    Args:
        keyword: Text to look for in artifact names.
    """
    res = get_vql().run_vql(
        "SELECT name, description FROM artifact_definitions() WHERE name =~ DfirKeyword",
        env={"DfirKeyword": "(?i)" + _re2_escape(keyword)},
    )
    from copilot.knowledge import is_live_only
    rows = [
        {"name": r.get("name"), "description": (r.get("description") or "").strip()[:300]}
        for r in res.get("results", [])
        if case_config.is_artifact_allowed(r.get("name", "")) and not is_live_only(r.get("name", ""))
    ]
    res["results"] = rows
    if not rows and not res.get("error"):
        return f"No allowed artifacts match '{keyword}'."
    return safe_json_truncate(res, max_records=40)


@tool
def describe_artifact(artifact_name: str) -> str:
    """
    Shows an artifact's description and parameters (name, type, default), so you can
    pass correct `parameters` to `collect_artifact`.
    Args:
        artifact_name: The exact artifact name.
    """
    res = get_vql().run_vql(
        "SELECT name, description, parameters FROM artifact_definitions(names=DfirName)",
        env={"DfirName": artifact_name},
    )
    if not res.get("results"):
        return safe_json_truncate(res) if res.get("error") else f"Artifact '{artifact_name}' not found."
    row = res["results"][0]
    from copilot.knowledge import artifact_info
    known = artifact_info(row.get("name", ""))
    info = {
        "name": row.get("name"),
        "allowed_for_this_case": case_config.is_artifact_allowed(row.get("name", "")),
        "heavy_needs_filter": case_config.is_heavy(row.get("name", "")),
        "evidence_location": known.get("location"),
        "what_it_shows": known.get("meaning"),
        "live_system_only": bool(known.get("live_only")),
        "disk_image_note": known.get("dead_disk_note"),
        "verified_parameters": known.get("params"),
        "tips": known.get("tips", []),
        "description": (row.get("description") or "").strip(),
        "parameters": [
            {k: p.get(k) for k in ("name", "type", "default", "description") if p.get(k) not in (None, "")}
            for p in (row.get("parameters") or [])
        ],
    }
    return _dump(info)


# ========================================================================
# DATABASE QUERY TOOLS (for the LLM to analyze collected data)
# ========================================================================

def _shown(total: int, shown: int) -> str:
    if total > shown:
        return (f"Showing {shown} of {total} matches (oldest first). Narrow the time window, "
                f"event_type or source to see the rest.")
    return f"{total} match." if total == 1 else f"{total} matches."


@tool
def query_timeline(start_time: Optional[str] = None, end_time: Optional[str] = None,
                   event_type: Optional[str] = None, source: Optional[str] = None) -> str:
    """
    Timeline of the case: one event per timestamp found in the collected data, in UTC,
    oldest first. Each event names the field its time came from (timestamp_desc, e.g.
    'Created0x10' vs 'Modified0x10'). Reports the total number of matches, and how many
    matching records have no timestamp at all (e.g. PSReadline history) so they aren't missed;
    find those with search_iocs or pivot_entity.
    Args:
        start_time: ISO 8601 start (e.g., '2024-01-15T10:00:00Z'). Optional.
        end_time: ISO 8601 end (e.g., '2024-01-15T10:10:00Z'). Optional.
        event_type: One of: {types}. Optional.
        source: Filter by artifact source name (partial match). Optional.
    """
    try:
        res = case_db.query_timeline(start_time, end_time, event_type, source, limit=PAGE_EVENTS)
    except ValueError as e:
        return str(e)
    case_db.log_query("query_timeline", f"start={start_time} end={end_time} type={event_type} source={source}",
                      res["total"])
    out = {"summary": _shown(res["total"], len(res["events"])), "events": _slim(res["events"])}
    if res["undated"]:
        out["records_without_timestamps"] = res["undated"]
    if not res["total"] and not res["undated"]:
        return "No events found matching the criteria. Try broadening the time range or collecting more artifacts first."
    return _dump(out)


query_timeline.description = query_timeline.description.replace("{types}", ", ".join(EVENT_TYPE_NAMES))


@tool
def activity_histogram(start_time: Optional[str] = None, end_time: Optional[str] = None, bucket: str = "hour",
                       event_type: Optional[str] = None, source: Optional[str] = None) -> str:
    """
    Counts timeline events per time bucket and event type (UTC). Use it first to find
    bursts of activity worth zooming into, instead of reading raw timelines.
    Args:
        start_time: ISO 8601 start. Optional.
        end_time: ISO 8601 end. Optional.
        bucket: 'minute', 'hour' (default) or 'day'.
        event_type: Optional event type filter.
        source: Optional artifact source filter (partial match).
    """
    try:
        rows = case_db.activity_histogram(start_time, end_time, bucket, event_type, source)
    except ValueError as e:
        return str(e)
    case_db.log_query("activity_histogram", f"start={start_time} end={end_time} bucket={bucket} "
                      f"type={event_type} source={source}", len(rows))
    return _dump(rows) if rows else "No timeline events in that range."


@tool
def context_window(timestamp: str, minutes: int = 5, event_type: Optional[str] = None) -> str:
    """
    Everything on the timeline within ±`minutes` of a moment, across all collected
    sources: the main correlation tool once you have an event of interest
    (e.g. what ran right after a logon, what was written right after a download).
    Args:
        timestamp: ISO 8601 time of the event of interest (UTC).
        minutes: Window on each side (default 5, max 120).
        event_type: Optional event type filter.
    """
    from datetime import timedelta
    from copilot.normalize import parse_timestamp, format_ts
    center = parse_timestamp(timestamp, "time")
    if center is None:
        return f"Unrecognized timestamp '{timestamp}'. Use ISO 8601, e.g. 2020-09-19T02:35:54Z."
    delta = timedelta(minutes=max(1, min(int(minutes), 120)))
    return query_timeline.invoke({"start_time": format_ts(center - delta), "end_time": format_ts(center + delta),
                                  "event_type": event_type})


@tool
def search_iocs(keyword: str) -> str:
    """
    Case-insensitive substring search over every collected record (description, extracted
    fields and the full raw data) for an IOC or term: IP, hash, domain, filename, user, etc.
    Returns the total number of matching records and each record's first/last timestamp.
    Args:
        keyword: The IOC or search term to look for.
    """
    res = case_db.search_events(keyword, limit=PAGE_RECORDS)
    case_db.log_query("search_iocs", f"keyword={keyword}", res["total"])
    if not res["total"]:
        return f"No records found matching '{keyword}'. Try collecting more artifacts or using a different search term."
    return _dump({"summary": _shown(res["total"], len(res["records"])), "records": _slim(res["records"])})


@tool
def pivot_entity(entity: str, field: Optional[str] = None) -> str:
    """
    Find all records related to an entity. With `field`, matches only that extracted field
    (more precise); without it, searches everything.
    Use this to follow a user's activity, trace a process, or find everything about an IP.
    Args:
        entity: The value to pivot on (e.g., 'svchost.exe', 'jdoe', '192.168.1.50').
        field: Optional: user, process, command_line, path, hash, ip or event_id.
    """
    try:
        res = case_db.pivot_entity(entity, field, limit=PAGE_RECORDS)
    except ValueError as e:
        return str(e)
    case_db.log_query("pivot_entity", f"entity={entity} field={field}", res["total"])
    if not res["total"]:
        return f"No records found for '{entity}'" + (f" in field '{field}'." if field else ".")
    return _dump({"summary": _shown(res["total"], len(res["records"])), "records": _slim(res["records"])})


@tool
def get_event_detail(evidence_id: str) -> str:
    """
    Retrieve one record in full: its raw artifact data and every timestamp found in it.
    Args:
        evidence_id: The evidence ID to look up (returned by timeline/search/pivot tools).
    """
    result = case_db.get_event_detail(evidence_id)
    if not result:
        return f"No record found with evidence_id '{evidence_id}'."
    if result.get("raw_data"):
        result["raw_data"] = _cap_values(json.loads(result["raw_data"]))
    out = _dump({k: v for k, v in result.items() if v not in (None, "") and k != "ingested_at"})
    if len(out) > DETAIL_TOTAL_CHARS:
        out = out[:DETAIL_TOTAL_CHARS] + "...[truncated; ask for specific fields if needed]"
    return out


@tool
def case_summary() -> str:
    """
    Summary of the case database: records and timeline events, how many records have no
    timestamp, time range, breakdown by artifact, and ALL recorded findings (including ones
    from earlier sessions) with their IDs. Read this before writing a report or summary.
    """
    stats = case_db.get_stats()
    findings = case_db.get_findings()
    stats["findings"] = [{"id": f["finding_id"], "time_recorded": f["timestamp_utc"], "title": f["title"],
                          "confidence": f["confidence"], "mitre": f["mitre_technique"]} for f in findings]
    retracted = case_db.get_findings(include_retracted=True)
    stats["retracted_findings"] = len(retracted) - len(findings)
    return _dump(stats)


@tool
def record_finding(title: str, description: str, evidence_ids: list,
                   confidence: str = "medium", mitre_technique: Optional[str] = None,
                   timestamp_utc: Optional[str] = None) -> str:
    """
    Record a forensic finding for the final report. Call this whenever you discover
    something suspicious or malicious during analysis. The finding's time is taken
    automatically from the FIRST evidence ID, so list first the record that shows WHEN
    it happened (e.g. the 7045 event, the logon event), then supporting records.
    Record what the evidence shows; avoid "nothing found" findings unless the search was
    complete and appropriate (say exactly what was searched).
    Args:
        title: Short title (e.g., 'Webshell Detected').
        description: Detailed explanation of the finding (give corrected and recorded times if the host clock was skewed).
        evidence_ids: List of evidence_id strings that support this finding.
        confidence: 'low', 'medium', or 'high'.
        mitre_technique: MITRE ATT&CK technique ID (e.g., 'T1505.003'). Optional.
        timestamp_utc: Only used when none of the evidence has a timestamp (recorded host time). Optional.
    """
    from copilot.normalize import normalize_bound
    from copilot.report import finding_time
    if not evidence_ids:
        return "Not recorded: a finding needs at least one evidence_id from the case database."
    unknown = [e for e in evidence_ids if not case_db.get_event_detail(str(e))]
    if unknown:
        return (f"Not recorded: these evidence_ids do not exist in the case database: {unknown}. "
                f"Use IDs returned by query_timeline/search_iocs/pivot_entity.")
    confidence = (confidence or "medium").lower()
    if confidence not in ("low", "medium", "high"):
        confidence = "medium"
    window = (normalize_bound(case_config.start_time), normalize_bound(case_config.end_time)) \
        if case_config.has_scope else (None, None)
    when = finding_time(case_db, evidence_ids, window)  # from the FIRST evidence ID
    if when is None and timestamp_utc:
        try:
            when = normalize_bound(timestamp_utc)
        except ValueError:
            when = None
    fid = case_db.record_finding(title, description, evidence_ids, confidence, mitre_technique, when)
    return f"Finding recorded with ID: {fid} (time from evidence: {when or 'none'})"


# Functions and plugins that execute, write, upload, reach the network or change
# server state. Best-effort only: the real control is giving the API user a role
# without those permissions (see README).
_RAW_VQL_BLOCKLIST = re.compile(
    r"\b(execve|collect_client|hunt|hunt_add|hunt_update|create_flow_download|"
    r"http_client|upload|upload_\w+|copy|rm|write_\w+|mail|elastic_upload|splunk_upload|"
    r"server_set_metadata|client_set_metadata|client_delete|artifact_set|artifact_delete|"
    r"user_create|user_delete|user_grant|org_create|secret_add|set_client_monitoring|"
    r"set_server_monitoring|cancel_flow|delete_flow|inventory_add|label|notebook_\w+|"
    r"pskill|reg_set_value|reg_rm_\w+|starl|query)\s*\(",
    re.IGNORECASE,
)


EXPORT_MAX_ROWS = 200000
_EXPORT_COLUMNS = ["source", "event_type", "hostname", "description", "user", "process", "command_line",
                   "path", "hash", "ip", "event_id", "evidence_id"]


def _with_raw(rows: list) -> list:
    ids = [r["evidence_id"] for r in rows]
    raw = {}
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        q = f"SELECT evidence_id, raw_data FROM records WHERE evidence_id IN ({','.join('?' * len(chunk))})"
        raw.update({r[0]: r[1] for r in case_db.conn.execute(q, chunk)})
    for r in rows:
        r["raw_data"] = raw.get(r["evidence_id"], "")
    return rows


@tool
def export_results(query_type: str, start_time: Optional[str] = None, end_time: Optional[str] = None,
                   event_type: Optional[str] = None, source: Optional[str] = None,
                   keyword: Optional[str] = None, field: Optional[str] = None,
                   include_raw: bool = False) -> str:
    """
    Saves ALL rows of a query (not just the page you see) as a CSV file for the investigator
    to download, e.g. "give me the timeline of 02:30-03:00 as a file". Returns the file path.
    Args:
        query_type: 'timeline' (time window), 'search' (keyword) or 'pivot' (keyword in one field).
        start_time: For timeline: ISO 8601 start. Optional.
        end_time: For timeline: ISO 8601 end. Optional.
        event_type: For timeline: event type filter. Optional.
        source: For timeline: artifact source filter. Optional.
        keyword: For search/pivot: the term or entity.
        field: For pivot: user, process, command_line, path, hash, ip or event_id.
        include_raw: Add the full raw record (JSON) as a column.
    """
    import csv
    from copilot import outputs
    from copilot.report import Clock
    try:
        if query_type == "timeline":
            res = case_db.query_timeline(start_time, end_time, event_type, source, limit=EXPORT_MAX_ROWS)
            rows, total = res["events"], res["total"]
            clock = Clock(case_config.clock_offset_minutes)
            for r in rows:
                r["corrected_utc"] = clock.corrected(r["timestamp_utc"])
            header = (["corrected_utc"] if clock.skewed else []) + ["timestamp_utc", "timestamp_desc"] + _EXPORT_COLUMNS
            label = f"timeline {start_time or 'start'} to {end_time or 'end'}"
        elif query_type in ("search", "pivot"):
            if not keyword:
                return "export_results needs a keyword for search/pivot."
            res = (case_db.search_events(keyword, limit=EXPORT_MAX_ROWS) if query_type == "search"
                   else case_db.pivot_entity(keyword, field, limit=EXPORT_MAX_ROWS))
            rows, total = res["records"], res["total"]
            header = ["first_seen", "last_seen"] + _EXPORT_COLUMNS
            label = f"{query_type} '{keyword}'" + (f" in {field}" if field else "")
        else:
            return "query_type must be 'timeline', 'search' or 'pivot'."
    except ValueError as e:
        return str(e)
    if include_raw:
        rows = _with_raw(rows)
        header.append("raw_data")

    path = outputs.new_path(f"{query_type}_{keyword or source or 'results'}", "csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    note = f" (first {EXPORT_MAX_ROWS:,} of {total:,})" if total > len(rows) else ""
    outputs.register(path, "results", f"{label}: {len(rows):,} rows{note}")
    case_db.log_query("export_results", f"type={query_type} start={start_time} end={end_time} type={event_type} "
                      f"source={source} keyword={keyword} field={field}", len(rows))
    return f"Saved {len(rows):,} rows{note} to {path} (offered to the investigator as a download; don't write links)"


@tool
def export_evidence(evidence_ids: list) -> str:
    """
    Saves the complete original records (raw data and every timestamp) of the given
    evidence IDs as a JSON file for the investigator to download. Returns the file path.
    Args:
        evidence_ids: Evidence IDs to export.
    """
    from copilot import outputs
    records, missing = [], []
    for eid in evidence_ids:
        rec = case_db.get_event_detail(str(eid))
        if not rec:
            missing.append(eid)
            continue
        rec["raw_data"] = json.loads(rec["raw_data"]) if rec.get("raw_data") else None
        records.append(rec)
    if not records:
        return f"None of these evidence IDs exist: {missing}"
    path = outputs.new_path("evidence", "json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False, default=str)
    outputs.register(path, "evidence", f"{len(records)} evidence record(s): {', '.join(r['evidence_id'] for r in records)}")
    return (f"Saved {len(records)} record(s) to {path} (offered to the investigator as a download; don't write links)"
            + (f"; not found: {missing}" if missing else ""))


@tool
def dfir_guide(topic: str) -> str:
    """
    DFIR reference (no data access, cheap): what to check for an investigation question,
    what an event ID means, or what an artifact shows and how to query it.
    Args:
        topic: A playbook (initial_access, execution, persistence, lateral_movement,
               credential_access, collection_exfiltration, anti_forensics, timeline_basics, memory),
               an event ID (e.g. '4624'), an artifact name (e.g. 'Windows.NTFS.MFT'), or 'learned'
               for the lessons investigators approved on this server.
    """
    from copilot.knowledge import guide
    return guide(topic)


@tool
def propose_lesson(topic: str, lesson: str, unusable_on_images: Optional[bool] = None) -> str:
    """
    Proposes a lesson for the knowledge base, so this and future investigations (every case on this
    server) avoid a mistake or reuse a method. Only for something you VERIFIED in this
    investigation and that holds in general, e.g. "returns 0 rows on disk images because it calls
    lookupSID (seen in the flow log)", "the parameter is FileNameRegex, not FileRegex", "a FILE_CREATE
    and a RENAME_NEW_NAME with the same name in the same second are one file creation". Never case
    facts (IPs, hashes, hosts, users, times). The investigator approves it first.
    Args:
        topic: What it is about: an artifact name (e.g. 'Windows.Applications.Chrome.History'), a
               playbook (e.g. 'initial_access') or a short subject (e.g. 'Memory.windows.netscan').
        lesson: The lesson in one to three sentences, with the evidence that showed it.
        unusable_on_images: True if the artifact returns nothing from disk images (it is then refused).
    """
    from copilot import approvals, cases, lessons
    try:
        topic, lesson = lessons.check(topic, lesson, from_agent=True)
    except lessons.LessonError as e:
        return f"Lesson not proposed: {e}"
    flag = " [does not work on disk images]" if unusable_on_images else ""
    try:
        return approvals.run("lesson", f"{topic}{flag}: {lesson}",
                             {"topic": topic, "text": lesson, "unusable_on_images": bool(unusable_on_images)})
    except (approvals.ApprovalError, cases.CaseError) as e:
        return str(e)


@tool
def retract_finding(finding_id: str, reason: str) -> str:
    """
    Retract a finding that later evidence contradicts or that was recorded in error
    (e.g. "no archive found" after the USN journal shows one). Retracted findings leave
    the report body and are listed in an appendix with the reason.
    Args:
        finding_id: The finding ID (a unique prefix is enough).
        reason: Why it is retracted, citing the contradicting evidence or finding.
    """
    from copilot import approvals
    found = case_db.find_finding(finding_id)
    if not found:
        return f"No unique finding matches '{finding_id}'. Use case_summary to see finding IDs."
    if (found.get("status") or "active") != "active":
        return f"Finding {found['finding_id']} is already retracted."
    if not (reason or "").strip():
        return "Give a reason: the evidence or finding that contradicts it."
    try:
        return approvals.run("retract_finding", f"'{found['title']}' because: {reason}",
                             {"finding_id": found["finding_id"], "title": found["title"], "reason": reason})
    except approvals.ApprovalError as e:
        return str(e)


@tool
def server_vql_query(vql_query: str) -> str:
    """
    Executes read-only VQL on the Velociraptor SERVER. Disabled unless the case
    enables `agent.allow_raw_vql`. Prefer the database tools and `collect_artifact`.
    """
    if not case_config.allow_raw_vql:
        return ("Raw VQL is disabled for this case (agent.allow_raw_vql is false). "
                "Use collect_artifact, list_artifacts, describe_artifact and the database tools.")
    match = _RAW_VQL_BLOCKLIST.search(vql_query)
    if match:
        return f"Refused: '{match.group(1)}' is not allowed in raw VQL."
    res = get_vql().run_vql(vql_query)
    case_db.log_query("server_vql_query", vql_query, len(res.get("results", [])))
    return safe_json_truncate(res)


@tool
def export_case(include_csv: bool = True) -> str:
    """
    Exports the entire case database for offline investigation.
    Creates a ZIP file containing:
    - case.db (SQLite database - open with DB Browser, DBeaver, or Python)
    - records.csv (every collected row with extracted fields)
    - timeline.csv (one row per timestamp - open with Excel or Timeline Explorer)
    - findings.csv (all recorded findings)
    - audit_log.csv (full query audit trail for chain of custody)
    Args:
        include_csv: If True, also exports CSV files alongside the SQLite DB.
    """
    import csv
    import shutil
    import sqlite3
    import os
    from datetime import datetime

    from copilot import outputs
    import tempfile
    export_dir = tempfile.mkdtemp(prefix="case_export_")

    # Consistent copy of the live database
    with sqlite3.connect(os.path.join(export_dir, "case.db")) as dest:
        case_db.conn.backup(dest)

    if include_csv:
        cur = case_db.conn.cursor()
        exports = {
            "records": "SELECT * FROM records",
            "timeline": ("SELECT t.timestamp_utc, t.timestamp_desc, r.source, r.event_type, r.hostname, "
                         "r.description, r.user, r.process, r.command_line, r.path, r.hash, r.ip, r.event_id, "
                         "t.evidence_id FROM timeline t JOIN records r ON r.evidence_id = t.evidence_id "
                         "ORDER BY t.timestamp_utc"),
            "findings": "SELECT * FROM findings",
            "collections": "SELECT * FROM collections",
            "audit_log": "SELECT * FROM audit_log",
        }
        for table, query in exports.items():
            cur.execute(query)
            rows = cur.fetchall()
            if rows:
                csv_path = os.path.join(export_dir, f"{table}.csv")
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([desc[0] for desc in cur.description])
                    writer.writerows(rows)

    # Create the zip in the output directory
    zip_path = shutil.make_archive(outputs.new_path("case_export", "zip")[:-4], "zip", export_dir)

    # Cleanup export dir
    shutil.rmtree(export_dir)

    # Get file size
    size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    outputs.register(zip_path, "export", "Full case export (database + CSVs)")

    return (
        f"Case exported successfully!\n"
        f"File: {os.path.abspath(zip_path)}\n"
        f"Size: {size_mb:.2f} MB\n"
        f"Contents: case.db (SQLite)"
        + (" + records.csv, timeline.csv, findings.csv, collections.csv, audit_log.csv" if include_csv else "")
        + f"\n\nThe investigator can download this file and open:\n"
        f"- case.db with DB Browser for SQLite, DBeaver, or Python\n"
        f"- timeline.csv with Excel or Timeline Explorer for manual analysis"
    )


@tool
def list_cases() -> str:
    """Lists all investigations (cases): ID, name, evidence client, whether it has data, and which is active."""
    from copilot import cases
    return _dump(cases.list_cases())


@tool
def switch_case(case_id: str) -> str:
    """
    Makes another case the active investigation. Only when the investigator asks to.
    The conversation restarts in the new case after this turn, so finish your answer briefly.
    Args:
        case_id: The case ID from list_cases.
    """
    from copilot import approvals, cases
    known = {c["id"]: c for c in cases.list_cases()}
    if case_id not in known:
        return f"No case '{case_id}'. Known cases: {', '.join(known) or 'none'}."
    if case_id == cases.current_id():
        return f"Case '{case_id}' is already active."
    try:
        return approvals.run("switch_case", f"to '{case_id}' ({known[case_id]['name']})", {"case_id": case_id})
    except (approvals.ApprovalError, cases.CaseError) as e:
        return str(e)


@tool
def create_case(case_id: str, name: str, client_id: Optional[str] = None, start_time: Optional[str] = None,
                end_time: Optional[str] = None, description: Optional[str] = None,
                clock_offset_minutes: Optional[int] = None, iocs: Optional[dict] = None,
                copy_data_from: Optional[str] = None) -> str:
    """
    Creates a new investigation from what the investigator told you (does not switch to it).
    Only when the investigator asks. Use details they gave; leave the rest empty.
    IOCs mentioned in the description are also extracted automatically.
    Args:
        case_id: Short ID for the folder, e.g. 'acme-ws42' (letters, digits, - and _). Required.
        name: Case name. Required.
        client_id: Velociraptor client ID of the dead-disk image (C.xxxx), if known.
        start_time: Incident window start, ISO 8601 UTC. Optional.
        end_time: Incident window end, ISO 8601 UTC. Optional.
        description: What happened / what to determine, in the investigator's words.
        clock_offset_minutes: How far the host clock ran ahead of UTC, if known.
        iocs: Known indicators: {"ips": [], "domains": [], "hashes": [], "filenames": [], "users": []}.
        copy_data_from: ID of a case on the SAME evidence whose collected data should be copied
                        (saves re-collecting; findings are not copied).
    """
    from copilot import approvals, cases
    from copilot.iocs import extract_iocs, merge
    all_iocs = merge(iocs or {}, extract_iocs(description or ""))
    kwargs = {"case_id": case_id, "name": name, "client_id": client_id or "", "start_time": start_time or "",
              "end_time": end_time or "", "description": description or "",
              "clock_offset_minutes": clock_offset_minutes or 0, "iocs": all_iocs, "copy_from": copy_data_from}
    try:
        cases.create(**kwargs, dry_run=True)          # validate before asking the investigator
    except cases.CaseError as e:
        return str(e)
    found = {k: v for k, v in all_iocs.items() if v}
    summary = (f"'{case_id}' ({name})" + (f", client {client_id}" if client_id else "") +
               (f", IOCs {_dump(found)}" if found else "") +
               (f", copying data from '{copy_data_from}'" if copy_data_from else ""))
    try:
        result = approvals.run("create_case", summary, {"kwargs": kwargs})
    except (approvals.ApprovalError, cases.CaseError) as e:
        return str(e)
    return result + (f" IOCs: {_dump(found)}." if found else "") + " Ask the investigator whether to switch to it."


@tool
def update_case(client_id: Optional[str] = None, start_time: Optional[str] = None, end_time: Optional[str] = None,
                description: Optional[str] = None, clock_offset_minutes: Optional[int] = None,
                add_iocs: Optional[dict] = None, remove_iocs: Optional[dict] = None) -> str:
    """
    Changes the ACTIVE case's settings. Only when the investigator asks (e.g. "add 1.2.3.4 as an
    IOC", "the window is actually 18-19 Sept"). Pass only what changes.
    Args:
        client_id: New Velociraptor client ID.
        start_time: New window start (ISO 8601 UTC).
        end_time: New window end (ISO 8601 UTC).
        description: New description.
        clock_offset_minutes: Host clock offset ahead of UTC.
        add_iocs: IOCs to add, e.g. {"ips": ["1.2.3.4"]}.
        remove_iocs: IOCs to remove, same shape.
    """
    from copilot import cases
    from copilot.iocs import clean, merge
    changes = {k: v for k, v in {"client_id": client_id, "start_time": start_time, "end_time": end_time,
                                 "description": description,
                                 "clock_offset_minutes": clock_offset_minutes}.items() if v is not None}
    if add_iocs or remove_iocs:
        current = merge(case_config.iocs, add_iocs or {})
        drop = clean(remove_iocs or {})
        changes["iocs"] = {k: [v for v in current[k] if v not in drop[k]] for k in current}
    if not changes:
        return "Nothing to change."
    from copilot import approvals
    case_id = cases.current_id()
    try:
        cases.update(case_id, dry_run=True, **changes)   # validate before asking the investigator
    except cases.CaseError as e:
        return str(e)
    shown = {k: v for k, v in changes.items() if k != "iocs"}
    if "iocs" in changes:
        shown["iocs"] = {k: v for k, v in changes["iocs"].items() if v}
    try:
        result = approvals.run("update_case", f"case '{case_id}': {_dump(shown)}",
                               {"case_id": case_id, "changes": changes})
    except (approvals.ApprovalError, cases.CaseError) as e:
        return str(e)
    return f"{result} Case context now: {case_config.build_system_context()}"


@tool
def generate_report(executive_summary: str, recommendations: str, correlations: Optional[str] = None) -> str:
    """
    Generates the final DFIR report (Markdown) from the recorded findings and the case
    database. Call this at the END of an investigation, when the investigator asks.
    FIRST call case_summary: the summary must cover ALL active findings, including those
    recorded in earlier sessions, and contradicted findings should be retracted beforehand.
    Times (corrected and recorded), the evidence timeline, indicators, artifact
    explanations and audit log are filled in automatically; you only write:
    Args:
        executive_summary: 2-4 paragraphs for a non-technical reader: what happened, when (corrected
                           UTC), how, impact, and what remains unknown. Based only on recorded findings.
        recommendations: Bullet-point remediation and follow-up recommendations.
        correlations: How the findings connect (e.g. logon -> execution -> persistence), citing finding
                      titles and evidence IDs; state which links are proven and which are inferred.
    The file format is set by the investigator, not by you.
    """
    from copilot.report import build_report

    if not case_db.get_stats().get("total_records"):
        return ("Report not generated: the case database is empty, so there is no evidence to report on. "
                "Collect artifacts successfully first (see list_collections).")
    from copilot import outputs
    from copilot.report_html import to_html
    import re
    report_with_slots, charts = build_report(case_db, case_config, executive_summary, recommendations,
                                             correlations, with_charts=True)
    report_md = re.sub(r"\n\[\[chart:[a-z_]+\]\]\n", "\n", report_with_slots)  # charts are HTML-only
    from copilot import session
    # The Streamlit sidebar sets the formats per session; otherwise the case file decides.
    wanted = [f for f in (session.current().report_formats or []) if f in ("html", "md")] or case_config.report_formats
    stem = f"dfir_report_{case_config.case_name}"
    written = []
    base = outputs.new_path(stem, "md")[:-3]
    if "html" in wanted:
        with open(base + ".html", "w", encoding="utf-8") as f:
            f.write(to_html(report_with_slots, f"DFIR Report - {case_config.case_name}", charts))
        outputs.register(base + ".html", "report", "DFIR report (HTML)")
        written.append(base + ".html")
    if "md" in wanted:
        with open(base + ".md", "w", encoding="utf-8") as f:
            f.write(report_md)
        outputs.register(base + ".md", "report", "DFIR report (Markdown)")
        written.append(base + ".md")
    findings = case_db.get_findings()
    return (
        f"Report generated:\n" + "".join(f"- {p}\n" for p in written) +
        "The investigator gets these as download buttons automatically: do not write links or file paths "
        "in your answer.\n" +
        f"Sections: Executive Summary, Scope & Evidence, Findings Overview ({len(findings)}), Evidence Timeline, "
        f"Detailed Findings, Correlations, Indicators, Artifacts/Locations/Meanings, Recommendations, "
        f"appendices (collections, cited evidence records, retracted findings, audit log)."
    )


# ========================================================================
# Tool registry
# ========================================================================
tools = [
    search_clients, collect_artifact, check_collection, list_collections,
    list_artifacts, describe_artifact, analyze_memory, list_memory_plugins,
    activity_histogram, context_window, query_timeline, search_iocs, pivot_entity, get_event_detail,
    case_summary, record_finding, retract_finding, dfir_guide, propose_lesson,
    generate_report, export_case, export_results, export_evidence,
    list_cases, switch_case, create_case, update_case,
]
if case_config.allow_raw_vql:
    tools.append(server_vql_query)
tool_map = {t.name: t for t in tools}
