"""Lessons learned: proposed by the agent, approved by a person, then part of the knowledge base."""
import json

import pytest

from copilot import approvals, auth, collection, knowledge, lessons, session, tools
from copilot.collection import CollectionError
from conftest import FakeVQL

CHROME = "Windows.Applications.Chrome.History"
LOOKUP = "Returns 0 rows from disk images: it calls lookupSID, which is disabled there (seen in the flow log)."


def _propose(**extra):
    return tools.propose_lesson.invoke({"topic": CHROME, "lesson": LOOKUP, **extra})


def test_nothing_is_learned_without_a_person(case):
    assert "needs the investigator's approval" in _propose()
    assert lessons.all_lessons() == []


def test_approved_lesson_joins_the_knowledge_and_stops_the_collection(case, approve_all, monkeypatch):
    knowledge_before = knowledge.artifact_info(CHROME)
    out = _propose(unusable_on_images=True)
    assert "saved; it applies from now on" in out
    assert approve_all[0]["kind"] == "lesson" and LOOKUP in approve_all[0]["summary"]
    info = knowledge.artifact_info(CHROME)
    assert any(LOOKUP in tip for tip in info["tips"]) and info["live_only"]
    assert knowledge_before is not info and "learned_unusable" not in knowledge_before   # static entry untouched
    with pytest.raises(CollectionError, match="lesson learned on this server"):
        collection.collect(CHROME, vql=FakeVQL(), requested_by="agent")
    assert LOOKUP in knowledge.guide(CHROME) and LOOKUP in knowledge.guide("learned")
    saved = lessons.active()[0]
    assert saved["source"] == "agent" and saved["case"] and saved["status"] == "active"


def test_lessons_must_be_general(case, approve_all):
    out = tools.propose_lesson.invoke({"topic": "initial_access",
                                       "lesson": "The payload came from 194.61.24.102 over HTTP."})
    assert "must be general" in out and not approve_all
    assert "must be" in tools.propose_lesson.invoke({"topic": "x", "lesson": "short"})
    ok = tools.propose_lesson.invoke({"topic": "Windows.NTFS.ADSHunter",
                                      "lesson": "Zone.Identifier moves with the file: check the payload's "
                                                "current path, e.g. System32, not only Downloads."})
    assert "saved" in ok                       # artifact and stream names are not mistaken for domains


def test_auto_approved_lessons_wait_for_a_person(case, monkeypatch):
    from copilot.case_config import case_config
    case_config.data["agent"] = {"approvals": {"lesson": "auto"}}
    assert "saved as proposed" in _propose()
    assert lessons.active() == [] and len(lessons.proposed()) == 1


def test_with_sign_in_only_admins_make_lessons_active(case, monkeypatch):
    auth.add_user("alice", "correct horse battery", admin=True)
    auth.add_user("bob", "correct horse battery")
    monkeypatch.setattr(session.default(), "user", "bob")
    queue = []
    monkeypatch.setattr(approvals, "ASK", lambda r: queue.append(r) or "queued")
    _propose()
    assert "saved as proposed" in approvals.resolve(queue[0], True, actor="bob")
    lesson = lessons.proposed()[0]
    with pytest.raises(lessons.LessonError, match="Only an admin"):
        lessons.accept(lesson["id"], approver="bob")
    with pytest.raises(lessons.LessonError, match="Only an admin"):
        lessons.remove(lesson["id"], approver="bob")
    assert lessons.accept(lesson["id"], approver="alice")["status"] == "active"
    assert lessons.remove(lesson["id"], approver="alice") and lessons.all_lessons() == []


def test_duplicates_are_stored_once_and_the_cli_manages_lessons(case, capsys):
    first = lessons.add(CHROME, LOOKUP)
    assert lessons.add(CHROME, LOOKUP)["id"] == first["id"] and len(lessons.all_lessons()) == 1
    assert lessons.main(["list"]) == 0 and first["id"] in capsys.readouterr().out
    assert lessons.main(["remove", first["id"]]) == 0 and lessons.all_lessons() == []
    assert lessons.main(["remove", "nope"]) == 1


def test_list_artifacts_and_the_prompt_know_the_lessons(case, monkeypatch):
    lessons.add(CHROME, LOOKUP, unusable_on_images=True)
    vql = FakeVQL()
    vql.run_vql = lambda query, env=None, timeout=None: {"results": [{"name": CHROME, "description": "d"},
                                                                     {"name": "Windows.Applications.Firefox.History",
                                                                      "description": "d"}], "log": ""}
    monkeypatch.setattr(tools, "get_vql", lambda: vql)
    listed = tools.list_artifacts.invoke({"keyword": "history"})
    assert "Firefox" in listed and CHROME not in listed
    from copilot.case_config import case_config
    from copilot.prompts import build_system_prompt
    assert f"lessons so far about: {CHROME}" in build_system_prompt(case_config)


def test_lesson_file_is_never_half_written(case):
    lessons.add(CHROME, LOOKUP)
    with open(lessons.learned_file(), encoding="utf-8") as f:
        assert "lessons:" in f.read()
    assert json.dumps(lessons.all_lessons())               # plain data
