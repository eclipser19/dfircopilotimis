"""Headless tests of the Streamlit app (streamlit.testing), with fake Velociraptor and LLM."""
import os

import pytest
from langchain_core.messages import AIMessage

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

import copilot.database as database  # noqa: E402
from copilot import collection, outputs, tools  # noqa: E402
from copilot.case_config import case_config  # noqa: E402
from copilot.database import CaseDatabase  # noqa: E402
from conftest import CLIENT, FakeVQL  # noqa: E402

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


class ScriptedLLM:
    """Returns the given responses in order."""

    def __init__(self, *responses):
        self.responses = list(responses)

    def invoke(self, history):
        return self.responses.pop(0)


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    db = CaseDatabase(str(tmp_path))
    for module in (database, collection, tools, outputs):
        monkeypatch.setattr(module, "case_db", db)
    monkeypatch.setenv("DFIR_OUTPUT_DIR", str(tmp_path / "outputs"))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(case_config, "data", {
        "velociraptor": {"client_id": CLIENT},
        "collect": ["Generic.Client.Info"],
        "collection": {"agent_collections": "confirm"}})
    monkeypatch.setattr(collection, "get_vql", lambda: FakeVQL())
    monkeypatch.setattr(tools, "REPORT_FORMATS", None)      # the app sets it process-wide
    monkeypatch.setattr(collection, "CONFIRM", None)
    monkeypatch.setattr(collection, "time", __import__("types").SimpleNamespace(
        monotonic=lambda: 0, sleep=lambda s: None))
    return db


def _texts(at):
    return " ".join([m.value for m in at.markdown] + [c.value for c in at.caption] + [t.value for t in at.text])


def test_empty_case_offers_triage_and_runs_it(app_env):
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert "No data collected for this case yet" in _texts(at)
    at.checkbox(key="triage_analyze").uncheck().run()
    next(b for b in at.button if b.label == "Run triage").click().run()
    assert not at.exception
    assert "Generic.Client.Info -> FINISHED" in _texts(at)
    assert app_env.get_stats()["total_records"] == 1
    assert "No data collected" not in _texts(at)


def test_agent_report_appears_as_downloads(app_env):
    app_env.ingest_artifact_results([{"EventTime": "2020-09-19T03:36:23Z", "Message": "logon"}], "S", "D", "C.1")
    at = AppTest.from_file(APP, default_timeout=30)
    llm = ScriptedLLM(
        AIMessage(content="", tool_calls=[{"name": "generate_report", "id": "1",
                                           "args": {"executive_summary": "S", "recommendations": "- R"}}]),
        AIMessage(content="The report is ready."))
    at.session_state["llm_with_tools"] = llm
    at.session_state["finalizer"] = llm
    at.run()
    at.chat_input[0].set_value("Generate the report").run()
    assert not at.exception
    labels = [b.proto.label for b in at.get("download_button")]
    assert any(".html" in l for l in labels)
    assert "The report is ready." in _texts(at)


def test_agent_collection_waits_for_approval(app_env):
    app_env.ingest_artifact_results([{"Message": "x"}], "S", "D", "C.1")
    at = AppTest.from_file(APP, default_timeout=30)
    llm = ScriptedLLM(
        AIMessage(content="", tool_calls=[{"name": "collect_artifact", "id": "1",
                                           "args": {"artifact_name": "Windows.System.TaskScheduler"}}]),
        AIMessage(content="Waiting for approval."))
    at.session_state["llm_with_tools"] = llm
    at.session_state["finalizer"] = llm
    at.run()
    at.chat_input[0].set_value("Check scheduled tasks").run()
    assert not at.exception
    assert app_env.get_collections() == []                     # nothing ran yet
    approve = next(b for b in at.button if b.label == "Approve")
    approve.click().run()
    assert not at.exception
    assert [c["artifact"] for c in app_env.get_collections()] == ["Windows.System.TaskScheduler"]
    assert "Approved" in _texts(at)
    assert not [b for b in at.button if b.label == "Approve"]


def test_retract_finding_from_the_sidebar(app_env):
    app_env.ingest_artifact_results([{"Message": "x"}], "S", "D", "C.1")
    eid = app_env.search_events("x")["records"][0]["evidence_id"]
    app_env.record_finding("No ZIP archive found", "wrong", [eid], "medium")
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input(key="retract_reason").input("USN shows loot.zip").run()
    next(b for b in at.button if b.label == "Retract").click().run()
    assert not at.exception
    assert app_env.get_findings() == []
    assert app_env.get_findings(include_retracted=True)[0]["status_reason"] == "USN shows loot.zip"


def test_sidebar_report_format_reaches_the_tool(app_env):
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.multiselect(key="report_formats").select("md").run()
    assert tools.REPORT_FORMATS == ["html", "md"]
