import json
import re
from langchain_core.tools import tool
from copilot import collection
from copilot.collection import CollectionError
from copilot.vql_client import get_vql
from copilot.database import case_db
from copilot.case_config import case_config


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
    output += json.dumps(truncated, indent=2, default=str)

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
def collect_artifact(artifact_name: str, parameters: dict = None) -> str:
    """
    Collects a Velociraptor artifact from the case's dead-disk image and stores the
    results in the case database. Waits a limited time; if the collection is still
    running, it returns state RUNNING and a flow_id to pass to `check_collection` later.
    Only artifacts allowed by the case configuration can be collected.
    Args:
        artifact_name: The artifact name (e.g., 'Windows.EventLogs.EvtxHunter').
        parameters: Artifact parameters (e.g., {'IocRegex': 'evil'}). Use `describe_artifact` to see valid names.
    """
    try:
        return json.dumps(collection.collect(artifact_name, parameters), indent=2)
    except CollectionError as e:
        return f"Collection not started or failed: {e}"


@tool
def check_collection(flow_id: str) -> str:
    """
    Checks a collection started earlier. If it has finished, its results are ingested
    into the case database. Use for collections that `collect_artifact` reported as RUNNING.
    Args:
        flow_id: The flow ID returned by `collect_artifact` (e.g., 'F.CN3ABC...').
    """
    try:
        return json.dumps(collection.check(flow_id), indent=2)
    except CollectionError as e:
        return f"Could not check collection: {e}"


@tool
def list_collections() -> str:
    """Lists every collection started in this case, with its state and rows ingested."""
    rows = case_db.get_collections()
    if not rows:
        return "No collections have been started in this case yet."
    return json.dumps(rows, indent=2)


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
    rows = [
        {"name": r.get("name"), "description": (r.get("description") or "").strip()[:300]}
        for r in res.get("results", []) if case_config.is_artifact_allowed(r.get("name", ""))
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
    info = {
        "name": row.get("name"),
        "allowed_for_this_case": case_config.is_artifact_allowed(row.get("name", "")),
        "description": (row.get("description") or "").strip(),
        "parameters": [
            {k: p.get(k) for k in ("name", "type", "default", "description") if p.get(k) not in (None, "")}
            for p in (row.get("parameters") or [])
        ],
    }
    return json.dumps(info, indent=2)


# ========================================================================
# DATABASE QUERY TOOLS (for the LLM to analyze collected data)
# ========================================================================

@tool
def query_timeline(start_time: str = None, end_time: str = None,
                   event_type: str = None, source: str = None) -> str:
    """
    Query the case database for events within a time window.
    Args:
        start_time: ISO 8601 start (e.g., '2024-01-15T10:00:00Z'). Optional.
        end_time: ISO 8601 end (e.g., '2024-01-15T10:10:00Z'). Optional.
        event_type: Filter by type (event_log, execution, filesystem, network, persistence, browser, authentication, script_execution). Optional.
        source: Filter by artifact source name (partial match). Optional.
    """
    results = case_db.query_timeline(start_time, end_time, event_type, source)
    case_db.log_query("query_timeline", f"start={start_time} end={end_time} type={event_type} source={source}", len(results))
    if not results:
        return "No events found matching the criteria. Try broadening the time range or collecting more artifacts first."
    return json.dumps(results, indent=2)


@tool
def search_iocs(keyword: str) -> str:
    """
    Search the case database for any events mentioning a keyword (IP, hash, filename, user, process name, etc.).
    Args:
        keyword: The IOC or search term to look for.
    """
    results = case_db.search_events(keyword)
    case_db.log_query("search_iocs", f"keyword={keyword}", len(results))
    if not results:
        return f"No events found matching '{keyword}'. Try collecting more artifacts or using a different search term."
    return json.dumps(results, indent=2)


@tool
def pivot_entity(entity: str) -> str:
    """
    Find all events related to a specific entity (username, process, IP address, file path).
    Use this to trace lateral movement, follow a user's activity, or map a process tree.
    Args:
        entity: The entity to pivot on (e.g., 'svchost.exe', 'SYSTEM', '192.168.1.50').
    """
    results = case_db.pivot_entity(entity)
    case_db.log_query("pivot_entity", f"entity={entity}", len(results))
    if not results:
        return f"No events found for entity '{entity}'."
    return json.dumps(results, indent=2)


@tool
def get_event_detail(evidence_id: str) -> str:
    """
    Retrieve the full raw JSON data for a specific event by its evidence_id.
    Use this when you need to inspect the complete original artifact data.
    Args:
        evidence_id: The evidence ID to look up (returned by timeline/search/pivot tools).
    """
    result = case_db.get_event_detail(evidence_id)
    if not result:
        return f"No event found with evidence_id '{evidence_id}'."
    # Parse raw_data back to dict for readability
    if result.get("raw_data"):
        result["raw_data"] = json.loads(result["raw_data"])
    return json.dumps(result, indent=2)


@tool
def case_summary() -> str:
    """
    Returns a summary of all data currently in the case database:
    total events, sources collected, time range, and breakdown by artifact.
    """
    stats = case_db.get_stats()
    findings = case_db.get_findings()
    stats["recorded_findings"] = len(findings)
    if findings:
        stats["findings"] = findings
    return json.dumps(stats, indent=2)


@tool
def record_finding(title: str, description: str, evidence_ids: list,
                   confidence: str = "medium", mitre_technique: str = None,
                   timestamp_utc: str = None) -> str:
    """
    Record a forensic finding for the final report. Call this whenever you discover
    something suspicious or malicious during analysis.
    Args:
        title: Short title (e.g., 'Webshell Detected').
        description: Detailed explanation of the finding.
        evidence_ids: List of evidence_id strings that support this finding.
        confidence: 'low', 'medium', or 'high'.
        mitre_technique: MITRE ATT&CK technique ID (e.g., 'T1505.003'). Optional.
        timestamp_utc: When the event occurred. Optional.
    """
    if not evidence_ids:
        return "Not recorded: a finding needs at least one evidence_id from the case database."
    unknown = [e for e in evidence_ids if not case_db.get_event_detail(str(e))]
    if unknown:
        return (f"Not recorded: these evidence_ids do not exist in the case database: {unknown}. "
                f"Use IDs returned by query_timeline/search_iocs/pivot_entity.")
    fid = case_db.record_finding(title, description, evidence_ids, confidence, mitre_technique, timestamp_utc)
    return f"Finding recorded with ID: {fid}"


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
    - events.csv (all normalized events - open with Excel or Timeline Explorer)
    - findings.csv (all recorded findings)
    - audit_log.csv (full query audit trail for chain of custody)
    Args:
        include_csv: If True, also exports CSV files alongside the SQLite DB.
    """
    import csv
    import shutil
    import os
    from datetime import datetime

    export_dir = os.path.join("case_data", "export")
    os.makedirs(export_dir, exist_ok=True)

    # Copy the database
    shutil.copy2(case_db.db_path, os.path.join(export_dir, "case.db"))

    if include_csv:
        cur = case_db.conn.cursor()
        for table in ["events", "findings", "audit_log"]:
            cur.execute(f"SELECT * FROM {table}")
            rows = cur.fetchall()
            if rows:
                csv_path = os.path.join(export_dir, f"{table}.csv")
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([desc[0] for desc in cur.description])
                    writer.writerows(rows)

    # Create the zip
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"case_export_{timestamp}"
    zip_path = shutil.make_archive(
        os.path.join("case_data", zip_name), "zip", export_dir
    )

    # Cleanup export dir
    shutil.rmtree(export_dir)

    # Get file size
    size_mb = os.path.getsize(zip_path) / (1024 * 1024)

    return (
        f"Case exported successfully!\n"
        f"File: {os.path.abspath(zip_path)}\n"
        f"Size: {size_mb:.2f} MB\n"
        f"Contents: case.db (SQLite)"
        + (" + events.csv, findings.csv, audit_log.csv" if include_csv else "")
        + f"\n\nThe investigator can download this file and open:\n"
        f"- case.db with DB Browser for SQLite, DBeaver, or Python\n"
        f"- events.csv with Excel or Timeline Explorer for manual analysis"
    )


@tool
def generate_report(executive_summary: str, recommendations: str) -> str:
    """
    Generates the final DFIR report as a Markdown file using all recorded findings,
    the case database, and the audit log. Call this at the END of an investigation.
    
    The report structure is fixed by template — you only write the narrative sections.
    Args:
        executive_summary: A 2-4 paragraph executive summary of what happened, 
                          the impact, and what was found. Write this based on recorded findings.
        recommendations: Bullet-point remediation recommendations based on findings.
    """
    import os
    from datetime import datetime, timezone
    from jinja2 import Template
    from copilot.report_template import REPORT_TEMPLATE

    stats = case_db.get_stats()
    if not stats.get("total_events"):
        return ("Report not generated: the case database is empty, so there is no evidence to report on. "
                "Collect artifacts successfully first (see list_collections).")
    findings = case_db.get_findings()

    # Get audit log
    cur = case_db.conn.cursor()
    cur.execute("SELECT * FROM audit_log ORDER BY timestamp_utc ASC")
    audit_log = [dict(r) for r in cur.fetchall()]

    # Search for IOCs if provided in case.yaml
    iocs_searched = []
    if case_config.has_iocs:
        for ioc_type, values in case_config.iocs.items():
            for val in (values or []):
                hits = case_db.search_events(str(val))
                iocs_searched.append({"value": val, "type": ioc_type, "hits": len(hits)})

    # Render the template
    template = Template(REPORT_TEMPLATE)
    report_md = template.render(
        case_name=case_config.case_name,
        analyst=case_config.analyst,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        executive_summary=executive_summary,
        has_scope=case_config.has_scope,
        start_time=case_config.start_time,
        end_time=case_config.end_time,
        scope_description=case_config.description,
        sources=stats.get("by_source", []),
        total_events=stats.get("total_events", 0),
        earliest=stats.get("earliest", "N/A"),
        latest=stats.get("latest", "N/A"),
        findings=findings,
        iocs_searched=iocs_searched,
        recommendations=recommendations,
        audit_log=audit_log,
    )

    # Save to file
    os.makedirs("case_data", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join("case_data", f"dfir_report_{timestamp}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    return (
        f"Report generated successfully!\n"
        f"File: {os.path.abspath(report_path)}\n"
        f"Sections: Executive Summary, Scope & Evidence, Timeline, "
        f"Detailed Findings ({len(findings)}), IOC Summary, "
        f"Recommendations, Audit Log ({len(audit_log)} queries)\n"
        f"\nThe investigator can open this Markdown file or convert it to PDF."
    )


# ========================================================================
# Tool registry
# ========================================================================
tools = [
    search_clients, collect_artifact, check_collection, list_collections,
    list_artifacts, describe_artifact,
    query_timeline, search_iocs, pivot_entity, get_event_detail,
    case_summary, record_finding,
    generate_report, export_case,
]
if case_config.allow_raw_vql:
    tools.append(server_vql_query)
tool_map = {t.name: t for t in tools}
