"""Cases bound to accounts, and one active case per investigator session."""
import threading

import pytest
import yaml
from langchain_core.messages import HumanMessage

from copilot import auth, cases, conversation, outputs, session
from copilot.case_config import case_config
from copilot.database import case_db

PASSWORD = "correct horse battery"


@pytest.fixture
def team(tmp_path, monkeypatch):
    """alice (admin), bob and carol; no case open in the process session yet."""
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)                       # no legacy root case.yaml here
    auth.add_user("alice", PASSWORD, admin=True)
    auth.add_user("bob", PASSWORD)
    auth.add_user("carol", PASSWORD)
    return tmp_path


def as_user(monkeypatch, user):
    """Runs the following code as `user` in a session of their own (like a browser session)."""
    s = session.Session(user)
    monkeypatch.setattr(session, "PROVIDER", lambda: s)
    return s


def test_new_cases_belong_to_their_creator(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("bob-case", "Bob's case")
    data = yaml.safe_load(open(team / "cases" / "bob-case" / "case.yaml"))
    assert data["access"] == {"owner": "bob", "members": []}
    assert data["case"]["analyst"] == "bob"
    assert [c["id"] for c in cases.list_cases()] == ["bob-case"]
    assert [c["id"] for c in cases.list_cases(user="carol")] == []
    assert [c["id"] for c in cases.list_cases(user="alice")] == ["bob-case"]       # admin
    assert [c["id"] for c in cases.list_cases(user=None)] == ["bob-case"]          # no sign-in


def test_cases_from_before_sign_in_are_for_admins_only(team, monkeypatch):
    as_user(monkeypatch, None)
    cases.create("old", "Made without sign-in")
    assert "access" not in yaml.safe_load(open(team / "cases" / "old" / "case.yaml"))
    assert cases.list_cases(user="bob") == [] and len(cases.list_cases(user="alice")) == 1


def test_no_way_into_someone_elses_case(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("bob-case", "Bob's case")
    as_user(monkeypatch, "carol")
    for attempt in (lambda: cases.switch("bob-case"),
                    lambda: cases.create("mine", "Mine", copy_from="bob-case"),
                    lambda: cases.update("bob-case", name="pwned"),
                    lambda: cases.copy_data("bob-case", "bob-case"),
                    lambda: cases.set_access("bob-case", members=["carol"])):
        with pytest.raises(cases.CaseError) as e:
            attempt()
        assert str(e.value) == "No case 'bob-case'. Known cases: none."   # same as for a case that doesn't exist
    assert not session.current().has_case


def test_members_and_owner(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("shared", "Shared case")
    cases.switch("shared")
    assert cases.set_access("shared", members=["carol"]) == {"owner": "bob", "members": ["carol"]}
    with pytest.raises(cases.CaseError, match="Only an admin can change the case owner"):
        cases.set_access("shared", owner="carol")
    with pytest.raises(cases.CaseError, match="No such account"):
        cases.set_access("shared", members=["mallory"])
    row = case_db.conn.execute("SELECT query, actor FROM audit_log WHERE tool_name = 'case_access'").fetchone()
    assert "members [] -> ['carol']" in row["query"] and row["actor"] == "bob"

    as_user(monkeypatch, "carol")                                         # a member works on it...
    cases.switch("shared")
    cases.update("shared", description="seen by carol")
    with pytest.raises(cases.CaseError, match="owner or an admin"):       # ...but can't share it further
        cases.set_access("shared", members=["carol", "alice"])

    as_user(monkeypatch, "alice")                                         # an admin can hand it over
    cases.set_access("shared", owner="carol")
    assert yaml.safe_load(open(team / "cases" / "shared" / "case.yaml"))["access"] == {"owner": "carol",
                                                                                      "members": []}


def test_losing_access_closes_the_case(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("shared", "Shared case")
    cases.set_access("shared", members=["carol"])
    carol = as_user(monkeypatch, "carol")
    cases.switch("shared")
    assert cases.refresh() == ""
    as_user(monkeypatch, "bob")
    cases.set_access("shared", members=[])
    monkeypatch.setattr(session, "PROVIDER", lambda: carol)
    assert "no longer have access" in cases.refresh()
    assert not carol.has_case


def test_settings_changed_in_another_session_are_picked_up(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("shared", "Shared case")
    cases.set_access("shared", members=["carol"])
    bob = session.current()
    cases.switch("shared")
    cases.consume_settings_change()
    as_user(monkeypatch, "carol")
    cases.switch("shared")
    cases.update("shared", name="Renamed by carol")
    monkeypatch.setattr(session, "PROVIDER", lambda: bob)
    assert case_config.case_name == "Shared case"
    import os
    import time
    path = case_config.path
    os.utime(path, (time.time() + 5, time.time() + 5))          # make sure the mtime differs
    cases.refresh()
    assert case_config.case_name == "Renamed by carol" and cases.consume_settings_change()


def test_new_session_opens_a_case_the_user_may_open(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("b1", "B1")
    assert cases.new_session("bob").config.case_name == "B1"
    assert not cases.new_session("carol").has_case
    assert cases.new_session("alice").has_case


def test_sessions_work_on_different_cases_at_the_same_time(team, monkeypatch):
    as_user(monkeypatch, None)
    cases.create("a", "A")
    cases.create("b", "B")
    local = threading.local()
    monkeypatch.setattr(session, "PROVIDER", lambda: getattr(local, "session", None))
    sessions = {"a": cases.new_session(None), "b": cases.new_session(None)}
    results, start = {}, threading.Barrier(2)

    def work(case_id):
        local.session = sessions[case_id]
        cases.switch(case_id)
        start.wait()
        for i in range(20):
            case_db.ingest_artifact_results([{"Message": f"{case_id} row {i}"}], "S", client_id="C.1")
        results[case_id] = (case_config.case_name, case_db.get_stats()["total_records"],
                            {r["description"][:1] for r in case_db.search_events("row")["records"]})

    threads = [threading.Thread(target=work, args=(c,)) for c in sessions]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results["a"][0] == "A" and results["b"][0] == "B"
    assert results["a"][1] == results["b"][1] == 20
    assert results["a"][2] == {"a"} and results["b"][2] == {"b"}


def test_each_member_keeps_their_own_chat(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("shared", "Shared case")
    cases.set_access("shared", members=["carol"])
    cases.switch("shared")
    conversation.save("shared", [{"role": "user", "content": "before sign-in"}], [], user=None)
    ui, _ = conversation.load("shared", "sys", user="bob")
    assert ui[0]["content"] == "before sign-in"                    # first visit: the earlier chat
    conversation.save("shared", [{"role": "user", "content": "bob's question"}], [HumanMessage("q")], user="bob")
    conversation.save("shared", [{"role": "user", "content": "carol's question"}], [], user="carol")
    assert conversation.load("shared", "sys", user="bob")[0][0]["content"] == "bob's question"
    assert conversation.load("shared", "sys", user="carol")[0][0]["content"] == "carol's question"
    conversation.clear("shared", user="bob")
    assert conversation.load("shared", "sys", user="bob")[0] == []
    assert conversation.load("shared", "sys", user="carol")[0][0]["content"] == "carol's question"


def test_audit_log_records_who(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("b1", "B1")
    cases.switch("b1")
    case_db.log_query("query_timeline", "x", 3)
    assert case_db.conn.execute("SELECT actor FROM audit_log WHERE tool_name = 'query_timeline'").fetchone()[0] == "bob"


def test_shared_output_folder_has_a_folder_per_case(team, monkeypatch):
    monkeypatch.setenv("DFIR_OUTPUT_DIR", str(team / "uploads"))
    as_user(monkeypatch, None)
    cases.create("a", "A")
    cases.switch("a")
    assert outputs.output_dir() == str(team / "uploads" / "a")


def test_without_sign_in_everything_stays_open(team, monkeypatch):
    as_user(monkeypatch, None)
    cases.create("a", "A")
    cases.set_access("a", members=["bob"])                           # allowed: no sign-in in use
    assert cases.can_access("a") and cases.can_manage("a")
