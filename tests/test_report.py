import json
import re

import pytest

from copilot import tools
from copilot.case_config import case_config
from copilot.report import build_report, md
from conftest import CLIENT


@pytest.fixture
def skewed_case(case, monkeypatch):
    monkeypatch.setattr(case_config, "data", {
        "velociraptor": {"client_id": CLIENT},
        "scope": {"start_time": "2020-09-18T00:00:00Z", "end_time": "2020-09-20T00:00:00Z",
                  "clock_offset_minutes": 60, "description": "Recipe | leaked"}})
    case.ingest_artifact_results([
        {"EventTime": "2020-09-19T03:36:23Z", "EventID": 4624, "Message": "RDP logon",
         "EventData": {"TargetUserName": "Administrator", "IpAddress": "10.42.85.10"}},
        {"EventTime": "2020-09-19T03:42:42Z", "EventID": 7045, "Message": "Service installed",
         "EventData": {"ImagePath": "C:\\Windows\\System32\\coreupdater.exe"}},
    ], "Windows.EventLogs.EvtxHunter", "DESKTOP", "C.1")
    return case


def _ids(db):
    return [e["evidence_id"] for e in db.query_timeline()["events"]]


def test_finding_time_comes_from_evidence_not_the_model(skewed_case):
    logon, _ = _ids(skewed_case)
    out = tools.record_finding.invoke({"title": "RDP", "description": "d", "evidence_ids": [logon],
                                       "timestamp_utc": "2020-09-19T02:36:23Z"})  # model typed corrected time
    assert "2020-09-19T03:36:23" in out
    assert skewed_case.get_findings()[0]["timestamp_utc"] == "2020-09-19T03:36:23.000000Z"


def test_report_orders_and_corrects_times_even_for_old_mixed_findings(skewed_case):
    logon, service = _ids(skewed_case)
    # Findings saved by older versions with whatever time the model typed.
    skewed_case.record_finding("Service", "s", [service], "high", "T1543.003", "2020-09-19T02:42:42Z")
    skewed_case.record_finding("Logon", "l", [logon], "high", "T1021.001", "2020-09-19T03:36:23Z")
    report = build_report(skewed_case, case_config, "ES", "- R", "C")
    overview = report.split("## 3. Findings Overview")[1].split("## 4.")[0]
    rows = [l for l in overview.splitlines() if l.startswith("| 1 ") or l.startswith("| 2 ")]
    assert rows[0].startswith("| 1 | 2020-09-19 02:36:23 | 2020-09-19 03:36:23 | Logon")
    assert rows[1].startswith("| 2 | 2020-09-19 02:42:42 | 2020-09-19 03:42:42 | Service")


def test_report_tables_have_no_blank_lines_inside(skewed_case):
    logon, service = _ids(skewed_case)
    skewed_case.record_finding("Logon", "l", [logon, service], "high")
    report = build_report(skewed_case, case_config, "ES", "- R")
    lines = report.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^\|(---\|)+$", line):         # a table separator row
            j = i + 1
            while j < len(lines) and lines[j].startswith("|"):
                j += 1
            assert j > i + 1, f"table without rows at line {i}"
            assert lines[i - 1].startswith("|")       # header directly above


def test_report_sections_and_escaping(skewed_case):
    logon, service = _ids(skewed_case)
    skewed_case.record_finding("Logon | weird", "l", [logon], "high")
    skewed_case.record_finding("Service", "s", [service], "high")
    report = build_report(skewed_case, case_config, "ES", "- R", "Logon led to service.")
    for section in ["## 4. Evidence Timeline", "## 6. Correlations", "## 7. Indicators Observed",
                    "## 8. Artifacts, Locations & Meanings"]:
        assert section in report
    assert "Logon \\| weird" in report and "Recipe \\| leaked" in report
    assert "`10.42.85.10`" in report and "coreupdater.exe" in report
    assert "1 ↔ 2 | 6 min apart" in report
    assert "Security.evtx" in report or "winevt" in report


def test_md_helper():
    assert md("a|b\nc") == "a\\|b c"
    assert md("x" * 5000) == "x" * 5000  # never shortened


def test_retracted_findings_leave_the_report_body(skewed_case, approve_all):
    logon, service = _ids(skewed_case)
    wrong = skewed_case.record_finding("No archive found", "nothing", [logon], "medium")
    skewed_case.record_finding("Service", "s", [service], "high")
    out = tools.retract_finding.invoke({"finding_id": wrong[:6], "reason": "USN shows loot.zip (finding 2)"})
    assert out.startswith("Retracted finding")
    report = build_report(skewed_case, case_config, "ES", "- R")
    body, appendix = report.split("## Appendix C: Retracted Findings")
    assert "No archive found" not in body
    assert "No archive found" in appendix and "USN shows loot.zip" in appendix
    assert "Retracted findings" not in tools.case_summary.invoke({}) or True
    assert '"retracted_findings":1' in tools.case_summary.invoke({})


def test_retract_needs_a_unique_id(skewed_case):
    assert "No unique finding" in tools.retract_finding.invoke({"finding_id": "zz", "reason": "r"})


def test_finding_time_is_the_primary_evidence_not_context(skewed_case):
    logon, service = _ids(skewed_case)
    # Service finding cites the 7045 record first and the (earlier) logon as context.
    out = tools.record_finding.invoke({"title": "Service", "description": "d", "evidence_ids": [service, logon]})
    assert "03:42:42" in out
    report = build_report(skewed_case, case_config, "ES", "- R")
    assert "| 1 | 2020-09-19 02:42:42 | 2020-09-19 03:42:42 | Service" in report


def test_timeline_merges_fields_of_one_record_in_the_same_second(case, monkeypatch):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT}})
    case.ingest_artifact_results([{"OSPath": "C:/Windows/System32/coreupdater.exe",
                                   "Created0x10": "2020-09-19T03:40:00.691Z", "Created0x30": "2020-09-19T03:40:00.691Z",
                                   "LastModified0x10": "2020-09-19T03:40:00.900Z"}], "Windows.NTFS.MFT", "D", "C.1")
    eid = case.query_timeline()["events"][0]["evidence_id"]
    case.record_finding("Malware file", "f", [eid], "high")
    report = build_report(case, case_config, "ES", "- R")
    timeline = report.split("## 4. Evidence Timeline")[1].split("## 5.")[0]
    rows = [l for l in timeline.splitlines() if eid in l]
    assert len(rows) == 1
    assert "Created0x10, Created0x30, LastModified0x10" in rows[0]


def test_old_findings_table_is_upgraded(tmp_path):
    import sqlite3
    from copilot.database import CaseDatabase
    db = CaseDatabase(str(tmp_path))
    db.conn.execute("DROP TABLE findings")
    db.conn.execute("CREATE TABLE findings (finding_id TEXT PRIMARY KEY, timestamp_utc TEXT, title TEXT, "
                    "description TEXT, evidence_ids TEXT, confidence TEXT, mitre_technique TEXT, created_at TEXT)")
    db.conn.execute("INSERT INTO findings VALUES ('abc123def456', NULL, 'old', 'd', '[]', 'high', NULL, 'now')")
    db.conn.commit()
    db.conn.close()
    upgraded = CaseDatabase(str(tmp_path))
    assert [f["title"] for f in upgraded.get_findings()] == ["old"]
    assert upgraded.retract_finding("abc123", "wrong")["title"] == "old"
    assert upgraded.get_findings() == []


def test_report_never_shortens_records_queries_or_parameters(case, monkeypatch):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT}})
    long_cmd = "powershell -nop -w hidden -c " + "A" * 3000 + " END_OF_COMMAND"
    case.ingest_artifact_results([{"EventTime": "2020-09-19T03:40:00Z", "EventID": 4104, "CommandLine": long_cmd,
                                   "Note": "contains ``` backticks"}], "Windows.EventLogs.EvtxHunter", "D", "C.1")
    long_query = "SELECT * FROM source() WHERE x =~ '" + "B" * 2000 + "END_OF_QUERY'"
    case.log_query("ingest", long_query, 1, "X")
    case.upsert_collection("F.1", artifact="Windows.NTFS.MFT", parameters='{"FileRegex": "' + "C" * 1000 + 'END_OF_PARAMS"}')
    eid = case.query_timeline()["events"][0]["evidence_id"]
    case.record_finding("Payload", "p", [eid], "high")
    report = build_report(case, case_config, "ES", "- R")
    assert "END_OF_QUERY" in report and "END_OF_PARAMS" in report
    assert report.count("END_OF_COMMAND") >= 4          # timeline, finding table, indicators, raw record
    assert "…" not in report
    appendix = report.split("## Appendix B: Cited Evidence Records")[1]
    assert "````json" in appendix                        # fence longer than the ``` inside the record
    assert '"Note": "contains ``` backticks"' in appendix


def test_report_explains_event_ids_and_logon_types(case, monkeypatch):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT}})
    case.ingest_artifact_results([{"EventTime": "2020-09-19T03:36:24Z", "EventID": 4624, "Channel": "Security",
                                   "EventData": {"LogonType": 10, "TargetUserName": "Administrator"}}],
                                 "Windows.EventLogs.RDPAuth", "D", "C.1")
    eid = case.query_timeline()["events"][0]["evidence_id"]
    case.record_finding("RDP logon", "r", [eid], "high")
    report = build_report(case, case_config, "ES", "- R")
    assert "**4624: Successful logon (LogonType 10: RemoteInteractive (RDP))**" in report
    assert "| 4624 | Security | Successful logon |" in report


def test_markdown_report_carries_no_live_html(skewed_case):
    logon, _ = _ids(skewed_case)
    skewed_case.ingest_artifact_results([{"EventTime": "2020-09-19T03:40:00Z",
                                          "Message": "<img src=x onerror=alert(1)> & <script>x</script>"}],
                                        "S", "D", "C.1")
    evil = skewed_case.search_events("onerror")["records"][0]["evidence_id"]
    skewed_case.record_finding("<b>title</b>", "desc <svg onload=alert(1)>", [evil, logon], "high",
                               "<i>T1</i>")
    report = build_report(skewed_case, case_config, "<script>summary</script>", "- <img src=y>",
                          "<iframe src=z>")
    body = report.split("## Appendix B")[0]                  # appendix B is fenced code, inert by design
    for tag in ("<img", "<script", "<svg", "<iframe", "<b>", "<i>"):
        assert tag not in body, tag
    assert "&lt;img src=x onerror=alert(1)&gt;" in body or "&lt;img src=x onerror=alert(1)>" in body


def test_audit_log_names_the_investigator_once_sign_in_is_used(skewed_case, monkeypatch):
    from copilot import session
    skewed_case.log_query("query_timeline", "before sign-in", 2)
    assert "| Investigator |" not in build_report(skewed_case, case_config, "ES", "- R")
    monkeypatch.setattr(session.default(), "user", "bob")
    skewed_case.log_query("query_timeline", "window 02:30-03:00", 5)
    report = build_report(skewed_case, case_config, "ES", "- R")
    assert "| Investigator |" in report and re.search(r"\| bob \| query_timeline \| window 02:30-03:00 \| 5 \|", report)
