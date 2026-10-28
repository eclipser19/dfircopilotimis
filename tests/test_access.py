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


ONE, TWO, THREE = "C.abcdef0123456789", "C.2222222222222222", "C.3333333333333333"


def test_evidence_in_a_case_you_cannot_open_stays_out_of_reach(team, monkeypatch):
    as_user(monkeypatch, "bob")
    cases.create("bob-case", "Bob's case", client_id=ONE)
    as_user(monkeypatch, "carol")
    for client in (ONE, ONE.upper()):                                  # client IDs compare without case
        with pytest.raises(cases.CaseError, match="investigation you are not part of"):
            cases.create("mine", "Mine", client_id=client)
    cases.create("mine", "Mine", client_id=TWO)                        # evidence no case uses: hers to claim
    with pytest.raises(cases.CaseError, match="not part of"):
        cases.update("mine", client_id=ONE)
    as_user(monkeypatch, "bob")
    cases.set_access("bob-case", members=["carol"])
    as_user(monkeypatch, "carol")                                      # a member reaches the evidence
    cases.create("second-look", "Carol's own case on it", client_id=ONE)
    as_user(monkeypatch, "alice")
    cases.create("admin-case", "Admin", client_id=TWO)                 # admins may use any evidence


def test_server_can_keep_new_evidence_for_admins(team, monkeypatch):
    monkeypatch.setenv("DFIR_NEW_EVIDENCE", "admins")
    as_user(monkeypatch, "bob")
    with pytest.raises(cases.CaseError, match="Only an admin can open the first case"):
        cases.create("b", "B", client_id=ONE)
    cases.create("b", "B")                                             # a case without evidence is fine
    as_user(monkeypatch, "alice")
    cases.create("a", "A", client_id=ONE)
    cases.set_access("a", members=["bob"])
    as_user(monkeypatch, "bob")
    cases.update("b", client_id=ONE)                                   # reached through case a


def test_memory_images_of_other_investigations_are_not_offered(team, monkeypatch):
    images = team / "memory"
    images.mkdir()
    for name in ("a.mem", "b.mem"):
        (images / name).write_bytes(b"\0")
    monkeypatch.setenv("DFIR_MEMORY_DIR", str(images))
    as_user(monkeypatch, "bob")
    cases.create("bob-case", "Bob's case", memory_image="a.mem")
    assert [i["name"] for i in cases.usable_memory_images()] == ["a.mem", "b.mem"]
    as_user(monkeypatch, "carol")
    assert [i["name"] for i in cases.usable_memory_images()] == ["b.mem"]
    with pytest.raises(cases.CaseError, match="memory image a.mem is evidence"):
        cases.create("c", "C", memory_image="a.mem")


def test_search_clients_lists_only_clients_the_user_may_use(team, monkeypatch):
    from copilot import tools

    class Clients:
        def run_vql(self, query, env=None, **kwargs):
            return {"results": [{"client_id": c, "hostname": h} for c, h in
                                ((ONE, "BOBS-HOST"), (TWO, "NEW-IMAGE"), (THREE, "OTHER"))], "log": ""}

    monkeypatch.setattr(tools, "get_vql", lambda: Clients())
    as_user(monkeypatch, "bob")
    cases.create("bob-case", "Bob's case", client_id=ONE)
    as_user(monkeypatch, "alice")
    cases.create("alice-case", "Alice's case", client_id=THREE)
    assert "BOBS-HOST" in tools.search_clients.invoke({})              # admins see every client
    as_user(monkeypatch, "carol")
    listed = tools.search_clients.invoke({})
    assert "NEW-IMAGE" in listed and "BOBS-HOST" not in listed and ONE not in listed and "OTHER" not in listed
    assert "are not listed" in listed
    monkeypatch.setenv("DFIR_NEW_EVIDENCE", "admins")                  # unused evidence: admins only
    assert "NEW-IMAGE" not in tools.search_clients.invoke({})
    as_user(monkeypatch, "bob")
    assert "BOBS-HOST" in tools.search_clients.invoke({})


def test_a_case_keeps_the_evidence_its_data_came_from(team, monkeypatch):
    as_user(monkeypatch, None)
    cases.create("a", "A", client_id=ONE)
    cases.switch("a")
    cases.update("a", client_id=TWO)                                   # nothing collected yet: free to fix
    case_db.upsert_collection("F.1", client_id=TWO, artifact="X", state="FINISHED", rows_ingested=3)
    with pytest.raises(cases.CaseError, match=f"already holds data from Velociraptor client {TWO}"):
        cases.update("a", client_id=THREE)
    cases.update("a", name="Renamed", client_id=TWO)                   # the same source is fine
    cases.update("a", client_id="")                                    # clearing it is too...
    with pytest.raises(cases.CaseError, match="already holds data"):  # ...but not pointing it elsewhere
        cases.update("a", client_id=THREE)
    audit = [r[0] for r in case_db.conn.execute("SELECT query FROM audit_log WHERE tool_name = 'case_evidence'")]
    assert audit == [f"Velociraptor client {ONE} -> {TWO}", f"Velociraptor client {TWO} -> -"]
    cases.create("b", "B", client_id=THREE)
    with pytest.raises(cases.CaseError, match="different evidence clients"):
        cases.copy_data("a", "b")


def _bobs_case_with_data(monkeypatch):
    """bob's case on ONE with collected data, a finding and a dossier."""
    as_user(monkeypatch, "bob")
    cases.create("bob-case", "Bob's case", client_id=ONE)
    cases.switch("bob-case")
    case_db.ingest_artifact_results([{"EventTime": "2020-09-19T03:42:42Z", "Message": "service coreupdater"}],
                                    "S", "H", ONE)
    case_db.upsert_collection("F.1", client_id=ONE, artifact="S", state="FINISHED", rows_ingested=1)
    eid = case_db.query_timeline()["events"][0]["evidence_id"]
    fid = case_db.record_finding("coreupdater service installed", "d", [eid], "medium")
    case_db.save_dossier("## Intrusion timeline\n- service installed")
    return fid


def test_a_shared_case_is_a_starting_point_not_an_open_door(team, monkeypatch):
    fid = _bobs_case_with_data(monkeypatch)
    as_user(monkeypatch, "carol")
    assert cases.reusable_cases() == []
    with pytest.raises(cases.CaseError, match="No case 'bob-case'"):
        cases.create("mine", "Mine", copy_from="bob-case")

    as_user(monkeypatch, "bob")
    cases.set_access("bob-case", members=[])
    assert cases.set_sharing("bob-case", ["carol"]) == {"shared_with": ["carol"], "share_findings": False}
    cases.set_access("bob-case", members=[])                              # members saved: sharing stays
    assert cases.sharing_of(yaml.safe_load(open(team / "cases" / "bob-case" / "case.yaml"))) == (["carol"], False)

    as_user(monkeypatch, "carol")
    [shared] = cases.reusable_cases()
    assert shared["id"] == "bob-case" and shared["shared"] and not shared["findings"] and shared["owner"] == "bob"
    assert cases.list_cases() == []                                        # still not hers to open
    with pytest.raises(cases.CaseError, match="No case 'bob-case'"):
        cases.switch("bob-case")
    with pytest.raises(cases.CaseError, match="shared without its findings"):
        cases.create("mine", "Mine", copy_from="bob-case", copy_findings=True)
    cases.create("mine", "Mine", copy_from="bob-case")                     # its evidence and its data
    cases.switch("mine")
    assert case_config.client_id == ONE and case_db.get_stats()["total_records"] == 1
    assert case_db.get_findings() == [] and case_db.get_dossier() == {}

    as_user(monkeypatch, "bob")
    cases.set_sharing("bob-case", [cases.EVERYONE], findings=True)
    cases.switch("bob-case")
    reused = case_db.conn.execute("SELECT query, actor FROM audit_log WHERE tool_name = 'case_reused'").fetchone()
    assert reused["query"].startswith("copied into case mine") and reused["actor"] == "carol"

    as_user(monkeypatch, "carol")
    cases.create("second", "Second", copy_from="bob-case", copy_findings=True)
    cases.switch("second")
    [finding] = case_db.get_findings()
    assert finding["finding_id"] == fid and finding["origin"] == "case bob-case (bob)"
    assert case_db.get_dossier()["text"].startswith("Imported from case bob-case (bob): written ")
    assert "- service installed" in case_db.get_dossier()["text"]

    as_user(monkeypatch, "bob")
    cases.set_sharing("bob-case", [])                                      # withdrawn: copies stay
    as_user(monkeypatch, "carol")
    assert cases.reusable_cases() and all(not c["shared"] for c in cases.reusable_cases())
    with pytest.raises(cases.CaseError, match="No case 'bob-case'"):
        cases.copy_data("bob-case", "second")
    cases.create("third", "Third", client_id=ONE)       # her own cases are on that evidence: it stays reachable

    as_user(monkeypatch, "bob")
    cases.set_access("bob-case", members=["carol"])
    as_user(monkeypatch, "carol")                                          # members can't share it further
    with pytest.raises(cases.CaseError, match="Only the case owner or an admin can share"):
        cases.set_sharing("bob-case", [cases.EVERYONE])


def test_importing_into_an_existing_case_keeps_its_own_dossier(team, monkeypatch):
    _bobs_case_with_data(monkeypatch)
    cases.create("bob-two", "Bob's second look", client_id=ONE)
    cases.switch("bob-two")
    case_db.save_dossier("## Intrusion timeline\n- my own")
    counts = cases.copy_data("bob-case", "bob-two", findings=True)
    assert counts["records"] == 1 and counts["findings"] == 1 and counts["dossier"] == 0
    assert case_db.get_dossier()["text"].endswith("- my own")
    assert cases.copy_data("bob-case", "bob-two", findings=True)["findings"] == 0      # nothing twice


def test_evidence_section_for_the_report(team, monkeypatch):
    as_user(monkeypatch, None)
    cases.create("a", "A")
    cases.update("a", evidence={"image_name": "ws01.E01", "image_sha256": "AB" * 32})
    assert yaml.safe_load(open(team / "cases" / "a" / "case.yaml"))["evidence"] == \
        {"image_name": "ws01.E01", "image_sha256": "ab" * 32}
    with pytest.raises(cases.CaseError, match="64 hexadecimal"):
        cases.update("a", evidence={"image_sha256": "not a hash"})
    with pytest.raises(cases.CaseError, match="Unknown evidence field"):
        cases.update("a", evidence={"owner": "x"})
    cases.update("a", evidence={"image_sha256": ""})                   # emptied fields are dropped
    assert yaml.safe_load(open(team / "cases" / "a" / "case.yaml"))["evidence"] == {"image_name": "ws01.E01"}
    cases.update("a", evidence={"image_name": ""})
    assert "evidence" not in yaml.safe_load(open(team / "cases" / "a" / "case.yaml"))


def test_without_sign_in_everything_stays_open(team, monkeypatch):
    as_user(monkeypatch, None)
    cases.create("a", "A")
    cases.set_access("a", members=["bob"])                           # allowed: no sign-in in use
    assert cases.can_access("a") and cases.can_manage("a")
