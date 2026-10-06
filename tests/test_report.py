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
    assert md("x" * 10, 5) == "xxxx…"
