"""Investigators teach the copilot: notes, ratings, confirmed findings, lessons, export."""
import json

import pytest

from copilot import cases, commands, feedback, session
from copilot.case_config import case_config
from copilot.database import case_db
from copilot.prompts import build_system_prompt
from copilot.tools import case_summary


def test_notes_go_into_every_prompt_until_withdrawn(case):
    assert "INVESTIGATOR NOTES" not in build_system_prompt(case_config)
    note = feedback.add_note("The 10.0.0.5 logons are the administrator's own VPN, not the attacker.")
    assert session.current().settings_changed                     # the UIs rebuild the system prompt
    prompt = build_system_prompt(case_config)
    assert "## INVESTIGATOR NOTES" in prompt and "administrator's own VPN" in prompt
    assert prompt.index("INVESTIGATOR NOTES") < len(prompt)
    with pytest.raises(feedback.FeedbackError):
        feedback.add_note("   ")
    assert feedback.withdraw(note["feedback_id"]) and not feedback.withdraw(note["feedback_id"])
    assert "administrator's own VPN" not in build_system_prompt(case_config)
    audit = [r[0] for r in case.conn.execute("SELECT query FROM audit_log WHERE tool_name = 'feedback'")]
    assert audit[0].startswith(f"note {note['feedback_id']}:") and audit[1].endswith("withdrawn")


def test_a_wrong_answer_needs_the_correction_and_it_outranks_the_dossier(case):
    case.save_dossier("## Intrusion timeline\n- the C2 belongs to the dropper")
    with pytest.raises(feedback.FeedbackError, match="what is right"):
        feedback.rate("answer", -1, "", "What does memory show?", "The dropper owns the C2.")
    feedback.rate("answer", -1, "The C2 connection belongs to the injected spoolsv.exe.",
                  "What does memory show?", "The dropper owns the C2.")
    feedback.rate("answer", 1, "", "How did they get in?", "RDP after guessing.")   # right: kept, not a note
    prompt = build_system_prompt(case_config)
    notes_at, dossier_at = prompt.index("INVESTIGATOR NOTES"), prompt.index("CASE DOSSIER")
    assert notes_at < dossier_at and "injected spoolsv.exe" in prompt
    assert 'correcting the answer to: "What does memory show?"' in prompt
    assert "RDP after guessing" not in prompt
    assert [r["rating"] for r in case.get_feedback()] == [-1, 1]


def test_confirmed_findings_are_established_for_the_agent_and_the_report(case):
    from copilot.report import build_report
    case.ingest_artifact_results([{"EventTime": "2020-09-19T03:42:42Z", "Message": "service updater"}], "S", "H", "C.1")
    eid = case.query_timeline()["events"][0]["evidence_id"]
    fid = case.record_finding("Service updater installed", "d", [eid], "medium")
    with pytest.raises(feedback.FeedbackError):
        feedback.confirm_finding("nope")
    feedback.confirm_finding(fid)
    summary = json.loads(case_summary.invoke({}))
    assert summary["findings"][0]["confirmed_by"].startswith("investigator (")
    assert "`confirmed_by` (in `case_summary`) was checked by an investigator" in build_system_prompt(case_config)
    report = build_report(case, case_config, "ES", "- R")
    assert "- **Review:** confirmed by investigator (" in report and "| Confirmed |" in report


def test_chat_commands_add_list_and_withdraw_notes(case):
    assert "No notes in this case yet" in commands.handle("/notes")
    assert "Write the fact" in commands.handle("/note")
    reply = commands.handle("/note the server's clock was set to UTC-7 by mistake")
    assert reply.startswith("Noted (note 1)")
    assert "the server's clock was set to UTC-7" in commands.handle("/notes")
    assert commands.handle("/notes remove 1") == "Note 1 withdrawn."
    assert commands.handle("/notes remove 1") == "No active note 1."


def test_export_collects_every_case_and_skips_databases_from_before(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    s = session.Session(None)
    monkeypatch.setattr(session, "PROVIDER", lambda: s)
    for case_id in ("a", "b", "old"):
        cases.create(case_id, case_id.upper())
    cases.switch("a")
    feedback.add_note("note in a")
    feedback.rate("answer", -1, "fix in a", "q?", "answer text")
    cases.switch("b")
    fid = case_db.record_finding("Finding in b", "d", [], "low")
    feedback.confirm_finding(fid)
    feedback.rate("dossier", 1, "", "Investigate", "dossier text")
    import sqlite3
    (tmp_path / "data" / "old").mkdir(parents=True, exist_ok=True)
    sqlite3.connect(tmp_path / "data" / "old" / "case.db").execute("CREATE TABLE records (x)").connection.commit()
    path = feedback.export(str(tmp_path / "out.jsonl"), log=lambda *a: None)
    items = [json.loads(line) for line in open(path, encoding="utf-8")]
    assert {(i["case"], i["type"]) for i in items} == {("a", "note"), ("a", "answer"), ("b", "confirmed_finding"),
                                                        ("b", "dossier")}
    assert next(i for i in items if i["type"] == "answer")["answer"] == "answer text"
    assert feedback.main(["list"]) == 0
