import re
from datetime import datetime, timedelta, timezone

from copilot import charts, outputs, tools
from copilot.case_config import case_config
from conftest import CLIENT


def _seed(case, monkeypatch, title="RDP logon"):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT},
                                              "scope": {"start_time": "2020-09-18T00:00:00Z",
                                                        "end_time": "2020-09-20T00:00:00Z",
                                                        "clock_offset_minutes": 60}})
    case.ingest_artifact_results([
        {"EventTime": "2020-09-19T03:36:22Z", "EventID": 4624, "Channel": "Security",
         "EventData": {"TargetUserName": "<script>alert(1)</script>", "IpAddress": "10.42.85.10"}},
        {"EventTime": "2020-09-19T03:42:42Z", "EventID": 7045, "Channel": "System",
         "EventData": {"ImagePath": "C:\\Windows\\System32\\coreupdater.exe", "TargetUserName": "Administrator",
                       "IpAddress": "10.42.85.10"}},
    ], "Windows.EventLogs.EvtxHunter", "D", "C.1")
    logon, service = [e["evidence_id"] for e in case.query_timeline()["events"]]
    case.record_finding(title, "d", [logon], "high")
    case.record_finding("Service installed", "d", [service], "high")


def _report_html():
    tools.generate_report.invoke({"executive_summary": "S", "recommendations": "- R"})
    path = next(f["path"] for f in outputs.produced_since(0) if f["path"].endswith(".html"))
    return open(path, encoding="utf-8").read()


def test_html_report_has_the_four_charts_with_data_tables(case, monkeypatch):
    _seed(case, monkeypatch)
    page = _report_html()
    titles = re.findall(r'<figure class="viz[^"]*" aria-label="([^"]+)"', page)
    assert titles == ["Findings in sequence", "Activity over the incident window",
                      "Close-up: first to last finding", "Connections between findings and indicators"]
    assert page.count("<details><summary>Show data") == 4
    assert "<script" not in page.replace("&lt;script", "")         # evidence in charts is escaped
    assert "02:36:22" in page and "UTC (corrected)" in page          # charts use corrected time
    assert "10.42.85.10  ×2" in page                                  # shared indicator emphasised


def test_markdown_report_has_no_chart_slots(case, monkeypatch):
    _seed(case, monkeypatch)
    case_config.data["output"] = {"report_formats": ["html", "md"]}
    tools.generate_report.invoke({"executive_summary": "S", "recommendations": "- R"})
    md = open(next(f["path"] for f in outputs.produced_since(0) if f["path"].endswith(".md")), encoding="utf-8").read()
    assert "[[chart:" not in md


def test_chart_slot_text_in_evidence_cannot_inject_markup(case, monkeypatch):
    _seed(case, monkeypatch, title="[[chart:activity]] <img src=x onerror=alert(1)>")
    page = _report_html()
    assert "<img src=x" not in page


def test_nice_axis_and_marker_grouping():
    assert charts.nice_axis(21) == (30, 10)
    assert charts.nice_axis(3) == (3, 1)
    groups = charts._group_markers([(100, (None, 1, "a")), (105, (None, 2, "b")), (110, (None, 3, "c")),
                                    (300, (None, 4, "d"))])
    assert [g["label"] for g in groups] == ["1–3", "4"]
    assert charts._marker_levels([(100, 16), (110, 16), (300, 16)]) == [0, 1, 0]


def test_charts_skip_when_nothing_to_draw():
    start = datetime(2020, 9, 19, tzinfo=timezone.utc)
    assert charts.activity_chart("t", {}, start, start + timedelta(hours=1), 300, timedelta(0), [], "s") == ""
    assert charts.sequence_chart([], timedelta(0)) == ""
    assert charts.connections_chart([], []) == ""


def test_table_cells_are_sized_by_content():
    from copilot.report_html import to_html
    long_text = "word " * 40
    page = to_html(f"| UTC | Event |\n|---|---|\n| 2020-09-19 02:36:22 | {long_text} |", "t")
    assert '<td class="nw">2020-09-19 02:36:22</td>' in page
    assert '<td class="long">' in page


def test_connections_graph_highlights_without_scripts(case, monkeypatch):
    _seed(case, monkeypatch)
    page = _report_html()
    graph = page[page.index('<figure class="viz conn"'):]
    graph = graph[:graph.index("</figure>")]
    assert 'tabindex="0"' in graph                                  # clickable / keyboard focusable
    assert ":has(.fn1:is(:hover,:focus))" in graph                   # pure CSS, no <script>
    assert "<script" not in graph.replace("&lt;script", "")


def test_placeholder_and_source_values_are_not_indicators():
    from copilot.report import is_noise
    assert is_noise("ip", "-") and is_noise("ip", "LOCAL") and is_noise("ip", "null")
    assert not is_noise("ip", "10.42.85.10")
    assert is_noise("path", r"C:\Windows\System32\winevt\Logs\Security.evtx")
    assert not is_noise("path", r"C:\Users\mortysmith\Documents\loot.zip")
    assert not is_noise("user", "Administrator")
