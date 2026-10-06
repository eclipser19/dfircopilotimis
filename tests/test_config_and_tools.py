from copilot import tools
from copilot.case_config import case_config


def test_client_id_validation(monkeypatch):
    for bad in ["", "server", "C.123' OR 1", "C.zzzzzzzzzzzzzzzz"]:
        monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": bad}})
        assert case_config.client_id_error
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": "C.1a2b3c4d5e6f7a8b"}})
    assert case_config.client_id_error == ""


def test_allowlist_defaults_and_override(monkeypatch):
    monkeypatch.setattr(case_config, "data", {})
    assert case_config.is_artifact_allowed("Windows.EventLogs.EvtxHunter")
    assert case_config.is_artifact_allowed("Windows.System.Powershell.PSReadline")
    assert not case_config.is_artifact_allowed("Windows.System.PowerShell")

    monkeypatch.setattr(case_config, "data", {"artifacts": {"allow": ["*"]}})
    assert case_config.is_artifact_allowed("Custom.Thing")
    assert not case_config.is_artifact_allowed("Windows.System.CmdShell")  # denylist always wins


def test_raw_vql_disabled_by_default(case):
    assert "server_vql_query" not in tools.tool_map
    out = tools.server_vql_query.invoke({"vql_query": "SELECT * FROM info()"})
    assert "disabled" in out


def test_raw_vql_blocklist(case, monkeypatch):
    monkeypatch.setattr(case_config, "data", {"agent": {"allow_raw_vql": True}})
    for q in ["SELECT * FROM execve(argv=['id'])",
              "SELECT collect_client(client_id='C.1', artifacts='X') FROM scope()",
              "SELECT * FROM http_client(url='http://x')",
              "SELECT upload(file='/etc/passwd') FROM scope()"]:
        assert tools.server_vql_query.invoke({"vql_query": q}).startswith("Refused")


def test_re2_escape():
    assert tools._re2_escape("evtx hunter.exe (x)") == r"evtx hunter\.exe \(x\)"


def test_record_finding_rejects_unknown_evidence(case):
    case.ingest_artifact_results([{"Message": "Test row"}], "Test.Src", client_id="C.1")
    real_id = case.search_events("Test")["records"][0]["evidence_id"]

    out = tools.record_finding.invoke({"title": "t", "description": "d", "evidence_ids": ["made-up"]})
    assert out.startswith("Not recorded") and case.get_findings() == []

    out = tools.record_finding.invoke({"title": "t", "description": "d", "evidence_ids": []})
    assert out.startswith("Not recorded")

    out = tools.record_finding.invoke({"title": "t", "description": "d", "evidence_ids": [real_id]})
    assert out.startswith("Finding recorded") and len(case.get_findings()) == 1


def test_evidence_ids_are_stable(case):
    rows = [{"Message": "a"}, {"Message": "b"}]
    assert case.ingest_artifact_results(rows, "S", client_id="C.1") == 2
    assert case.ingest_artifact_results(iter(rows), "S", client_id="C.1") == 0
    assert case.get_stats()["total_records"] == 2


def test_linux_artifacts_allowed_but_shell_refused(monkeypatch):
    monkeypatch.setattr(case_config, "data", {})
    assert case_config.is_artifact_allowed("Linux.Forensics.Journal")
    assert case_config.is_artifact_allowed("Linux.Sys.Users")
    assert not case_config.is_artifact_allowed("Linux.Sys.BashShell")


def test_report_refused_on_empty_database(case):
    out = tools.generate_report.invoke({"executive_summary": "x", "recommendations": "y"})
    assert out.startswith("Report not generated")


def test_context_window_tool(case):
    case.ingest_artifact_results([
        {"EventTime": "2020-09-19T02:35:54Z", "Message": "RDP logon"},
        {"EventTime": "2020-09-19T02:38:00Z", "Message": "download"},
        {"EventTime": "2020-09-19T03:30:00Z", "Message": "later"},
    ], "S", client_id="C.1")
    out = tools.context_window.invoke({"timestamp": "2020-09-19T02:35:54Z", "minutes": 5})
    assert "RDP logon" in out and "download" in out and "later" not in out
    assert "Unrecognized" in tools.context_window.invoke({"timestamp": "soon"})


def test_tool_output_is_compact_and_not_duplicated(case):
    case.ingest_artifact_results([{"EventTime": "2020-09-19T02:35:54Z", "Message": "logon",
                                   "EventData": {"TargetUserName": "Administrator", "IpAddress": "10.42.85.10"}}],
                                 "Windows.EventLogs.RDPAuth", "DESKTOP-SDN1RPT", "C.1")
    out = tools.query_timeline.invoke({})
    assert "\n" not in out                    # compact JSON
    assert '"ip"' not in out and '"hostname"' not in out
    assert out.count("10.42.85.10") == 1      # only inside the description


def test_event_detail_is_capped(case):
    case.ingest_artifact_results([{"EventTime": "2020-09-19T02:35:54Z", "Blob": "x" * 50000}], "S", client_id="C.1")
    eid = case.query_timeline()["events"][0]["evidence_id"]
    assert len(tools.get_event_detail.invoke({"evidence_id": eid})) < 7000
