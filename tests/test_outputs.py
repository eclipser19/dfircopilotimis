import csv
import json
import os

from copilot import outputs, tools
from copilot.case_config import case_config
from copilot.report_html import to_html
from conftest import CLIENT


def _seed(case, monkeypatch):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT},
                                              "scope": {"start_time": "2020-09-18T00:00:00Z",
                                                        "end_time": "2020-09-20T00:00:00Z",
                                                        "clock_offset_minutes": 60}})
    rows = [{"EventTime": f"2020-09-19T03:{m:02d}:00Z", "EventID": 4624, "Message": f"logon {m}",
             "EventData": {"TargetUserName": "Administrator"}} for m in range(120 // 2)]
    rows.append({"EventTime": "2020-09-19T03:40:00Z", "Message": "<script>alert('pwned')</script> evil | pipe",
                 "CommandLine": "<img src=x onerror=alert(1)>"})
    case.ingest_artifact_results(rows, "Windows.EventLogs.EvtxHunter", "DESKTOP", "C.1")


def test_report_is_written_as_html_and_markdown_and_registered(case, monkeypatch):
    _seed(case, monkeypatch)
    eid = case.search_events("pwned")["records"][0]["evidence_id"]
    case.record_finding("Script in log", "d", [eid], "high")
    out = tools.generate_report.invoke({"executive_summary": "S", "recommendations": "- R"})
    files = outputs.produced_since(0)
    assert [os.path.splitext(f["path"])[1] for f in files] == [".html", ".md"]
    assert all(f["path"] in out for f in files)
    assert all(f["path"].startswith(os.environ["DFIR_OUTPUT_DIR"]) for f in files)


def test_html_report_neutralizes_evidence_html(case, monkeypatch):
    _seed(case, monkeypatch)
    eid = case.search_events("pwned")["records"][0]["evidence_id"]
    case.record_finding("Script in log", "d", [eid], "high")
    tools.generate_report.invoke({"executive_summary": "S", "recommendations": "- R"})
    html_path = next(f["path"] for f in outputs.produced_since(0) if f["path"].endswith(".html"))
    page = open(html_path, encoding="utf-8").read()
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;script&gt;alert" in page            # shown as text
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "<table>" in page                        # Markdown tables became HTML tables


def test_to_html_blocks_javascript_links():
    page = to_html("[click](javascript:alert(1)) <b>raw</b>", "t")
    assert 'href="javascript' not in page and "<b>raw</b>" not in page


def test_export_results_has_every_row_and_corrected_times(case, monkeypatch):
    _seed(case, monkeypatch)
    out = tools.export_results.invoke({"query_type": "timeline", "start_time": "2020-09-19T03:00:00Z",
                                       "end_time": "2020-09-19T04:00:00Z"})
    path = out.rsplit(" to ", 1)[1]
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 61                          # more than one tool page (50)
    assert rows[0]["corrected_utc"] == "2020-09-19 02:00:00"
    assert outputs.produced_since(0)[-1]["kind"] == "results"


def test_export_search_with_raw(case, monkeypatch):
    _seed(case, monkeypatch)
    out = tools.export_results.invoke({"query_type": "search", "keyword": "pwned", "include_raw": True})
    path = out.rsplit(" to ", 1)[1]
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1 and "<script>" in json.loads(rows[0]["raw_data"])["Message"]
    assert "needs a keyword" in tools.export_results.invoke({"query_type": "pivot"})


def test_export_evidence(case, monkeypatch):
    _seed(case, monkeypatch)
    eid = case.search_events("pwned")["records"][0]["evidence_id"]
    out = tools.export_evidence.invoke({"evidence_ids": [eid, "nope"]})
    path = out.split(" to ")[1].split(";")[0]
    data = json.load(open(path, encoding="utf-8"))
    assert data[0]["raw_data"]["CommandLine"] == "<img src=x onerror=alert(1)>"
    assert "not found: ['nope']" in out


def test_new_paths_are_safe_and_unique(case):
    a = outputs.new_path("../../etc/passwd x", "csv")
    b = outputs.new_path("../../etc/passwd x", "csv")
    open(a, "w").close()
    c = outputs.new_path("../../etc/passwd x", "csv")
    assert os.path.dirname(a) == outputs.output_dir()
    assert ".." not in os.path.basename(a) and "/" not in os.path.basename(a)
    assert a == b and c != a
