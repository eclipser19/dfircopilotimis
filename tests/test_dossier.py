"""Investigate once, then answer: the case dossier and the system prompts that carry it."""
import pytest
from langchain_core.messages import AIMessage

from copilot import dossier
from copilot.case_config import case_config
from copilot.prompts import build_system_prompt


class ScriptedLLM:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.histories = []

    def invoke(self, history):
        self.histories.append(list(history))
        return self.responses.pop(0)


def test_the_investigation_writes_the_dossier_every_prompt_then_carries(case):
    assert dossier.prompt_section() == "" and "CASE DOSSIER" not in build_system_prompt(case_config)
    llm = ScriptedLLM(AIMessage(content="", tool_calls=[{"name": "case_summary", "id": "1", "args": {}}]),
                      AIMessage(content="## Intrusion timeline\n- 02:20 UTC logon from 203.0.113.5\n## Gaps\n- none"))
    entry = dossier.investigate(llm, llm, emit=lambda *a: None, extra="The triage has just run.")
    asked = llm.histories[0][1].content
    assert asked.startswith("[Copilot] Investigate this case once") and "The triage has just run." in asked
    assert "earlier investigation" not in asked
    assert entry["steps"] == 2 and entry["text"].endswith("## Gaps\n- none") and entry["findings"] == 0
    assert dossier.latest()["dossier_id"] == entry["dossier_id"]
    prompt = build_system_prompt(case_config)
    assert "## CASE DOSSIER" in prompt and "- 02:20 UTC logon from 203.0.113.5" in prompt
    audit = case.conn.execute("SELECT query FROM audit_log WHERE tool_name = 'investigate'").fetchone()[0]
    assert audit.startswith(f"dossier {entry['dossier_id']}:")

    # Again: it starts from the dossier it replaces.
    llm = ScriptedLLM(AIMessage(content="## Intrusion timeline\n- updated"))
    second = dossier.investigate(llm, llm, emit=lambda *a: None)
    assert "earlier investigation is in your system prompt" in llm.histories[0][1].content
    assert "- 02:20 UTC logon" in llm.histories[0][0].content                 # the old one, to check
    assert dossier.latest()["dossier_id"] == second["dossier_id"] != entry["dossier_id"]
    assert "- updated" in build_system_prompt(case_config)


def test_no_answer_is_no_dossier(case):
    llm = ScriptedLLM(AIMessage(content=""))
    with pytest.raises(dossier.DossierError, match="without a dossier"):
        dossier.investigate(llm, None, emit=lambda *a: None)
    assert dossier.latest() == {}


def test_a_long_dossier_is_shortened_in_the_prompt(case):
    case.save_dossier("x" * (dossier.PROMPT_CHARS + 500))
    section = dossier.prompt_section()
    assert "[... shortened" in section and len(section) < dossier.PROMPT_CHARS + 1500


def test_budget_is_larger_than_a_question_and_configurable(case):
    case_config.data["agent"] = {"max_steps": 10, "max_tokens_per_turn": 100000}
    assert dossier.budget() == (dossier.MIN_STEPS, 300000)
    case_config.data["agent"] = {"max_steps": 30, "investigate_tokens": 900000}
    assert dossier.budget() == (60, 900000)
    case_config.data["agent"] = {"investigate_steps": 15}
    assert dossier.budget()[0] == 15


def test_times_the_model_shifted_are_flagged_in_the_stored_dossier(case):
    case_config.data["scope"] = {"clock_offset_minutes": 60}
    case.ingest_artifact_results([{"EventTime": "2020-09-19T03:36:23Z", "Message": "rdp client to 10.42.85.115"}],
                                 "S", "H", "C.1")
    eid = case.query_timeline()["events"][0]["evidence_id"]
    llm = ScriptedLLM(AIMessage(content=f"## Intrusion timeline\n- 03:36:23 UTC (recorded 04:36:23) RDP out (`{eid}`)\n"
                                        f"- 02:36:23 UTC (recorded 03:36:23) the same, right (`{eid}`)\n## Gaps\n- none"))
    entry = dossier.investigate(llm, llm, emit=lambda *a: None)
    assert entry["time_mismatches"] == 1
    assert "## Time check (automatic, no model)" in entry["text"] and "recorded 04:36:23 is not a time" in entry["text"]
    assert "A time\nlisted under \"Time check\" is wrong" in build_system_prompt(case_config)


def test_the_checklists_the_case_needs_come_with_the_investigation(case, monkeypatch):
    assert "Checklist (web_attack)" not in dossier.prompt()
    case.ingest_artifact_results([{"Name": "httpd.exe", "Path": "C:\\xampp\\apache\\bin\\httpd.exe"}],
                                 "Memory.windows.pslist.PsList", "H", "memory:x")
    case_config.data["memory"] = {"image": "x.mem"}
    asked = dossier.prompt()
    assert "The data shows a web server (httpd.exe" in asked and "Checklist (web_attack)" in asked
    assert "Checklist (memory)" in asked


def test_a_long_dossier_keeps_its_gaps_and_leaves_out_whole_sections():
    text = ("## Intrusion timeline\n" + "- step\n" * 200 + "## Hypotheses\n" + "- maybe\n" * 3000 +
            "## Gaps\n- web logs not collected\n")
    fitted = dossier.fit(text, 4000)
    assert "## Gaps\n- web logs not collected" in fitted and "## Intrusion timeline" in fitted
    assert "## Hypotheses" not in fitted and fitted.endswith("[... left out for length: Hypotheses]")
    assert dossier.fit("short", 4000) == "short"
