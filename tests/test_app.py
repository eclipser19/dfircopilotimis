"""Headless tests of the Streamlit app (streamlit.testing), with fake Velociraptor and LLM."""
import os

import pytest
from langchain_core.messages import AIMessage

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

import copilot.database as database  # noqa: E402
from copilot import cases, collection, outputs, tools  # noqa: E402
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
    for module in (database, collection, tools, outputs, cases):
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


def test_chat_command_switches_case_without_llm(app_env, tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.setattr(case_config, "path", case_config.path)
    cases.create("beta", "Beta laptop")
    at = AppTest.from_file(APP, default_timeout=30).run()   # no LLM configured at all
    at.chat_input[0].set_value("/case beta").run()
    assert not at.exception
    assert case_config.case_name == "Beta laptop"
    assert "Now in case `beta`" in _texts(at)
    assert len(at.session_state["chat_history"]) == 1         # fresh conversation: system prompt only
    cases.consume_switch()


def test_new_case_form_extracts_iocs_and_creates(app_env, tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.setattr(case_config, "path", case_config.path)
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input(key="nc_name").input("Guided Szechuan").run()
    at.text_area(key="nc_desc").input("Brute force from 194[.]61[.]24[.]102, payload coreupdater.exe").run()
    next(b for b in at.button if b.label == "Extract from description").click().run()
    assert at.text_area(key="nc_ioc_ips").value == "194.61.24.102"
    assert at.text_area(key="nc_ioc_filenames").value == "coreupdater.exe"
    next(b for b in at.button if b.label == "Create and open").click().run()
    assert "Case ID must be" in _texts(at) or at.error                 # required field missing
    at.text_input(key="nc_id").input("szechuan-guided").run()
    next(b for b in at.button if b.label == "Create and open").click().run()
    assert not at.exception
    assert case_config.case_name == "Guided Szechuan" and case_config.iocs["ips"] == ["194.61.24.102"]
    assert "Now in case `szechuan-guided`" in _texts(at)
    cases.consume_switch()


def test_case_settings_panel_saves(app_env, tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.setattr(case_config, "path", case_config.path)
    cases.create("beta", "Beta laptop")
    cases.switch("beta")
    cases.consume_switch()
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_area(key="cs_beta_ioc_ips").input("10.0.0.5\nnot-an-ip").run()
    at.number_input(key="cs_beta_offset").set_value(60).run()
    next(b for b in at.button if b.label == "Save settings").click().run()
    assert not at.exception
    assert case_config.iocs["ips"] == ["10.0.0.5"] and case_config.clock_offset_minutes == 60
    assert "10.0.0.5" in at.session_state["chat_history"][0].content     # the agent sees the new settings


@pytest.fixture
def two_app_cases(app_env, tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.setattr(case_config, "path", case_config.path)
    cases.create("alpha", "Alpha")
    cases.create("beta", "Beta")
    cases.switch("alpha")
    cases.consume_switch()
    yield
    cases.consume_switch()


def _ask(at, text, *replies):
    llm = ScriptedLLM(*replies)
    at.session_state["llm_with_tools"] = llm
    at.session_state["finalizer"] = llm
    at.chat_input[0].set_value(text).run()


def test_switching_cases_saves_and_restores_each_chat(two_app_cases):
    at = AppTest.from_file(APP, default_timeout=30).run()
    _ask(at, "alpha question", AIMessage(content="alpha answer"))
    at.chat_input[0].set_value("/case beta").run()
    assert "alpha answer" not in _texts(at) and "New conversation" in _texts(at)
    _ask(at, "beta question", AIMessage(content="beta answer"))
    at.chat_input[0].set_value("/case alpha").run()
    texts = _texts(at)
    assert "alpha answer" in texts and "beta answer" not in texts and "Conversation restored" in texts
    agent_memory = [m.content for m in at.session_state["chat_history"]]
    assert "alpha question" in agent_memory and "beta question" not in agent_memory


def test_chat_survives_an_app_restart(two_app_cases):
    at = AppTest.from_file(APP, default_timeout=30).run()
    _ask(at, "remember me", AIMessage(content="noted"))
    fresh = AppTest.from_file(APP, default_timeout=30).run()      # new browser session / restarted app
    assert "noted" in _texts(fresh)
    assert "remember me" in [m.content for m in fresh.session_state["chat_history"]]


def test_agent_switching_mid_answer_keeps_that_answer_in_the_old_case(two_app_cases):
    at = AppTest.from_file(APP, default_timeout=30).run()
    _ask(at, "please switch to beta",
         AIMessage(content="", tool_calls=[{"name": "switch_case", "id": "1", "args": {"case_id": "beta"}}]),
         AIMessage(content="Switching to beta now."))
    assert case_config.case_name == "Beta"
    assert "Switching to beta now." not in _texts(at)             # beta starts clean
    at.chat_input[0].set_value("/case alpha").run()
    assert "Switching to beta now." in _texts(at)                 # the answer was saved with alpha


def test_new_conversation_button(two_app_cases):
    at = AppTest.from_file(APP, default_timeout=30).run()
    _ask(at, "old topic", AIMessage(content="old answer"))
    next(b for b in at.button if "New conversation" in b.label).click().run()
    assert "old answer" not in _texts(at)
    assert len(at.session_state["chat_history"]) == 1
    assert "old answer" not in _texts(AppTest.from_file(APP, default_timeout=30).run())
