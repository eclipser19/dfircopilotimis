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
