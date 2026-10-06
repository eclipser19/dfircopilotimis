import json
import time
from langchain_core.tools import tool
from copilot.vql_client import vql
from copilot.database import case_db
from copilot.case_config import case_config


def safe_json_truncate(res_dict: dict, max_records: int = 50) -> str:
    """Safely truncates the results to avoid blowing up the LLM context."""
    results = res_dict.get("results", [])
    log = res_dict.get("log", "")

    output = ""
    if log and log.strip():
        output += f"--- VELOCIRAPTOR LOG / ERRORS ---\n{log.strip()}\n\n"

    truncated = results[:max_records]
    output += json.dumps(truncated, indent=2)

    if len(results) > max_records:
        output += f"\n\n... [System Note: Truncated {len(results) - max_records} records. Try narrowing the timeframe or parameters.]"

    return output


# ========================================================================
# VELOCIRAPTOR COLLECTION TOOLS
# ========================================================================

@tool
def search_clients() -> str:
    """Finds all enrolled clients/endpoints in Velociraptor (including Virtual Dead-Disk clients)."""
    query = "SELECT client_id, os_info.hostname, os_info.system FROM clients()"
    res = vql.run_vql(query)
    return safe_json_truncate(res)


@tool
def collect_artifact(client_id: str, artifact_name: str, parameters: dict = None) -> str:
    """
    Collects a Velociraptor artifact on a client AND stores results in the case database.
    After collection, use timeline/search/pivot tools to analyze the data.
    Args:
        client_id: The ID of the client (e.g., 'C.123456789').
        artifact_name: The name of the artifact (e.g., 'Windows.EventLogs.EvtxHunter').
        parameters: A dictionary of artifact parameters (e.g., {'EvtxGlob': '**/*.evtx'}).
    """
    params = parameters or {}
    safe_client = client_id.replace("'", "")
    safe_artifact = artifact_name.replace("'", "")

    # 1. Schedule the collection
    if params:
        env_entries = ", ".join([
            f"`{k}`='{str(v).replace(chr(39), chr(39)+chr(39))}'"
            for k, v in params.items()
        ])
        schedule_query = (
            f"SELECT collect_client("
            f"client_id='{safe_client}', "
            f"artifacts=['{safe_artifact}'], "
            f"env=dict({env_entries})"
            f") AS flow FROM scope()"
        )
    else:
        schedule_query = (
            f"SELECT collect_client("
            f"client_id='{safe_client}', "
            f"artifacts=['{safe_artifact}']"
            f") AS flow FROM scope()"
        )

    res = vql.run_vql(schedule_query)
    case_db.log_query("collect_artifact", schedule_query, 0, safe_artifact)

    if not res.get("results"):
        return safe_json_truncate(res)

    flow_obj = res["results"][0].get("flow")
    if not flow_obj or "flow_id" not in flow_obj:
        return safe_json_truncate(res)

    flow_id = flow_obj["flow_id"]

    # 2. Poll for completion (up to 60 seconds)
    artifacts_with_results = []
    for _ in range(30):
        poll_query = f"SELECT state, total_collected_rows, artifacts_with_results FROM flows(client_id='{safe_client}', flow_id='{flow_id}')"
        poll_res = vql.run_vql(poll_query)
        if poll_res.get("results"):
            row = poll_res["results"][0]
            if row.get("state") == "FINISHED":
                artifacts_with_results = row.get("artifacts_with_results") or []
                break
        time.sleep(2)

    # Wait for results to flush
    time.sleep(1)

    # 3. Retrieve results and ingest into the case database
    total_ingested = 0
    sample_results = []

    if artifacts_with_results:
        for sub_artifact in artifacts_with_results:
            source_query = f"SELECT * FROM source(client_id='{safe_client}', flow_id='{flow_id}', artifact='{sub_artifact}')"
            sub_res = vql.run_vql(source_query)
            rows = sub_res.get("results", [])

            if rows:
                # Get hostname from the client
                hostname_res = vql.run_vql(f"SELECT os_info.hostname FROM clients(search='host:{safe_client}')")
                hostname = "Unknown"
                if hostname_res.get("results"):
                    hostname = hostname_res["results"][0].get("os_info.hostname", "Unknown")

                ingested = case_db.ingest_artifact_results(rows, sub_artifact, hostname)
                total_ingested += ingested
                sample_results.extend(rows[:5])  # Keep a small sample for the LLM

            case_db.log_query("collect_artifact", source_query, len(rows), sub_artifact)

    # Return a summary instead of dumping all raw data
    stats = case_db.get_stats()
    summary = {
        "status": "success",
        "artifact": safe_artifact,
        "sub_artifacts_collected": artifacts_with_results,
        "rows_ingested": total_ingested,
        "database_total_events": stats["total_events"],
        "database_sources": stats["by_source"],
        "sample_data": sample_results[:5]
    }
    return json.dumps(summary, indent=2)


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
    fid = case_db.record_finding(title, description, evidence_ids, confidence, mitre_technique, timestamp_utc)
    return f"Finding recorded with ID: {fid}"


@tool
def server_vql_query(vql_query: str) -> str:
    """
    Executes arbitrary VQL directly on the SERVER. Use as a fallback when
    the other tools don't cover your needs.
    """
    res = vql.run_vql(vql_query)
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
    search_clients, collect_artifact,
    query_timeline, search_iocs, pivot_entity, get_event_detail,
    case_summary, record_finding,
    generate_report, export_case, server_vql_query
]
tool_map = {t.name: t for t in tools}
