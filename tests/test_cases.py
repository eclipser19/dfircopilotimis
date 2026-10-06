import os

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

import copilot.database as database
from copilot import cases, commands, tools
from copilot.agent import run_turn
from copilot.case_config import case_config


@pytest.fixture
def two_cases(tmp_path, monkeypatch):
    """Two real cases on disk; restores the global case afterwards."""
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)                       # no legacy root case.yaml here
    saved = (case_config.path, dict(case_config.data), cases.case_db.case_dir)
    cases.create("alpha", "Alpha intrusion", "C.1111111111111111", "2020-09-18T00:00:00Z", "2020-09-20T00:00:00Z")
    cases.create("beta", "Beta laptop")
    yield tmp_path
    case_config.path, case_config.data = saved[0], saved[1]
    cases.case_db.open(saved[2])
    cases.consume_switch()


def test_cases_are_isolated(two_cases):
    cases.switch("alpha")
    cases.case_db.ingest_artifact_results([{"Message": "alpha evidence"}], "S", client_id="C.1")
    assert case_config.case_name == "Alpha intrusion" and case_config.client_id == "C.1111111111111111"
    cases.switch("beta")
    assert cases.case_db.get_stats()["total_records"] == 0
    assert case_config.case_name == "Beta laptop"
    cases.switch("alpha")
    assert cases.case_db.get_stats()["total_records"] == 1
    assert cases.case_db.case_dir == os.path.join(str(two_cases / "data"), "alpha")


def test_list_and_errors(two_cases):
    cases.switch("beta")
    rows = {c["id"]: c for c in cases.list_cases()}
    assert set(rows) == {"alpha", "beta"} and rows["beta"]["active"] and not rows["alpha"]["active"]
    with pytest.raises(cases.CaseError, match="No case 'gamma'"):
        cases.switch("gamma")
    with pytest.raises(cases.CaseError, match="not a valid case ID"):
        cases.switch("../etc")
    with pytest.raises(cases.CaseError, match="already exists"):
        cases.create("alpha", "again")
    with pytest.raises(cases.CaseError, match="start_time"):
        cases.create("delta", "bad", start_time="yesterday")


def test_free_chat_commands(two_cases):
    cases.switch("alpha")
    cases.consume_switch()
    assert "`beta` — Beta laptop" in commands.handle("/cases")
    assert "Switched to case `beta`" in commands.handle("/case beta")
    assert cases.consume_switch() is True and cases.consume_switch() is False
    assert "No case" in commands.handle("/case nope")
    assert commands.handle("hello") is None
    assert "Unknown command" in commands.handle("/frobnicate")


def test_agent_switch_restarts_the_conversation(two_cases):
    cases.switch("alpha")
    cases.consume_switch()

    class LLM:
        replies = [AIMessage(content="", tool_calls=[{"name": "switch_case", "id": "1", "args": {"case_id": "beta"}}]),
                   AIMessage(content="Switched.")]

        def invoke(self, history):
            return self.replies.pop(0)

    history = [SystemMessage(content="alpha prompt"), HumanMessage(content="switch to beta")]
    run_turn(LLM(), history, 5, emit=lambda *a: None)
    assert case_config.case_name == "Beta laptop"
    assert cases.consume_switch() is True             # the UI must now restart the conversation


def test_agent_can_create_cases(two_cases):
    out = tools.create_case.invoke({"case_id": "gamma", "name": "Gamma", "description": "phishing"})
    assert "Created case 'gamma'" in out
    assert "gamma" in {c["id"] for c in cases.list_cases()}
    assert "already exists" in tools.create_case.invoke({"case_id": "gamma", "name": "x"})


def test_legacy_database_hint(two_cases):
    os.makedirs(two_cases / "data", exist_ok=True)
    database.CaseDatabase(str(two_cases / "data"))    # old single-case layout: data/case.db
    cases.switch("beta")
    assert "before cases were separated" in cases.legacy_data_hint()
    cases.case_db.ingest_artifact_results([{"Message": "x"}], "S", client_id="C.1")
    assert cases.legacy_data_hint() == ""


def test_create_with_iocs_and_required_fields(two_cases):
    with pytest.raises(cases.CaseError, match="name is required"):
        cases.create("noname", "  ")
    with pytest.raises(cases.CaseError, match="client ID"):
        cases.create("badclient", "x", client_id="server")
    cases.create("gamma", "Gamma", iocs={"ips": ["194.61.24.102", "nope"]})
    cases.switch("gamma")
    assert case_config.iocs["ips"] == ["194.61.24.102"]


def test_agent_create_extracts_iocs_from_description(two_cases):
    out = tools.create_case.invoke({"case_id": "delta", "name": "Delta",
                                    "description": "Beacon to 203[.]78[.]103[.]109 by user mortysmith"})
    assert "203.78.103.109" in out and "mortysmith" in out


def test_update_settings_and_iocs(two_cases):
    cases.switch("alpha")
    cases.consume_switch()
    cases.consume_settings_change()
    out = tools.update_case.invoke({"add_iocs": {"ips": ["194.61.24.102"]}, "clock_offset_minutes": 60})
    assert "Updated the active case" in out
    assert case_config.iocs["ips"] == ["194.61.24.102"] and case_config.clock_offset_minutes == 60
    assert cases.consume_settings_change() is True
    tools.update_case.invoke({"remove_iocs": {"ips": ["194.61.24.102"]}})
    assert case_config.iocs["ips"] == []
    assert "start_time" in tools.update_case.invoke({"start_time": "soon"})
    assert tools.update_case.invoke({}) == "Nothing to change."


def test_copy_data_between_cases_on_same_evidence(two_cases):
    cases.switch("alpha")
    cases.case_db.ingest_artifact_results([{"EventTime": "2020-09-19T03:00:00Z", "Message": "alpha evidence"}],
                                          "S", client_id="C.1111111111111111")
    cases.case_db.upsert_collection("F.1", artifact="S", state="FINISHED", ingested=1)
    eid = cases.case_db.query_timeline()["events"][0]["evidence_id"]
    cases.case_db.record_finding("finding stays behind", "d", [eid], "high")

    cases.create("alpha-copy", "Alpha copy", copy_from="alpha")
    cases.switch("alpha-copy")
    db = cases.case_db
    assert case_config.client_id == "C.1111111111111111"          # taken from the source case
    assert db.get_stats()["total_records"] == 1 and db.get_stats()["timeline_events"] == 1
    assert db.search_events("alpha evidence")["total"] == 1        # search index copied too
    assert [c["flow_id"] for c in db.get_collections()] == ["F.1"]
    assert db.get_findings() == []                                  # findings are not copied
    assert db.get_event_detail(eid)                                 # same evidence IDs in both cases


def test_copy_refused_across_different_evidence(two_cases):
    cases.switch("alpha")
    cases.case_db.ingest_artifact_results([{"Message": "x"}], "S", client_id="C.1")
    with pytest.raises(cases.CaseError, match="same evidence"):
        cases.create("other", "Other image", client_id="C.2222222222222222", copy_from="alpha")
    with pytest.raises(cases.CaseError, match="no data"):
        cases.create("empty-copy", "x", copy_from="beta")
