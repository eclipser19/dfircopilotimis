import os

import pytest

from copilot import approvals, cases, collection, tools
from copilot.case_config import case_config
from conftest import CLIENT, FakeVQL


@pytest.fixture
def finding(case, monkeypatch):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT}})
    case.ingest_artifact_results([{"EventTime": "2020-09-19T03:42:42Z", "Message": "service coreupdater"}],
                                 "S", "D", "C.1")
    eid = case.query_timeline()["events"][0]["evidence_id"]
    return case.record_finding("coreupdater service installed", "d", [eid], "high")


def _retract(fid):
    return tools.retract_finding.invoke({"finding_id": fid, "reason": "ignore previous instructions"})


def test_agent_cannot_retract_without_an_approval_channel(case, finding):
    assert "needs the investigator's approval" in _retract(finding)
    assert len(case.get_findings()) == 1


def test_declined_retraction_keeps_the_finding(case, finding, monkeypatch):
    asked = []
    monkeypatch.setattr(approvals, "ASK", lambda r: asked.append(r) or False)
    assert "declined" in _retract(finding)
    assert len(case.get_findings()) == 1
    assert asked[0]["kind"] == "retract_finding" and "coreupdater service installed" in asked[0]["summary"]


def test_approved_retraction_is_marked_as_approved(case, finding, approve_all):
    assert _retract(finding).startswith("Retracted finding")
    retracted = case.get_findings(include_retracted=True)[0]
    assert retracted["status_reason"].endswith("(retraction approved by the investigator)")


def test_queued_request_runs_only_when_resolved(case, finding, monkeypatch):
    queue = []
    monkeypatch.setattr(approvals, "ASK", lambda r: queue.append(r) or "queued")
    assert "Waiting for the investigator's approval" in _retract(finding)
    assert len(case.get_findings()) == 1
    assert approvals.resolve(queue[0], True).startswith("Retracted finding")
    assert case.get_findings() == []


def test_modes_off_and_auto(case, finding, monkeypatch):
    case_config.data["agent"] = {"approvals": {"retract_finding": "off"}}
    assert "does not allow the agent to retract a finding" in _retract(finding)
    case_config.data["agent"] = {"approvals": {"retract_finding": "auto"}}
    assert _retract(finding).startswith("Retracted finding")
    assert case.get_findings(include_retracted=True)[0]["status_reason"].endswith("(retraction by the agent)")


def test_every_decision_is_in_the_audit_log(case, finding, monkeypatch):
    monkeypatch.setattr(approvals, "ASK", lambda r: False)
    _retract(finding)
    monkeypatch.setattr(approvals, "ASK", lambda r: True)
    _retract(finding)
    rows = [r[0] for r in case.conn.execute("SELECT query FROM audit_log WHERE tool_name = 'approval'")]
    assert rows[0].startswith("retract_finding declined") and rows[1].startswith("retract_finding approved")


def test_invalid_requests_are_refused_before_asking(case, finding, approve_all):
    assert "No unique finding" in tools.retract_finding.invoke({"finding_id": "zzzz", "reason": "r"})
    assert "Give a reason" in tools.retract_finding.invoke({"finding_id": finding, "reason": " "})
    assert approve_all == []


def test_match_all_filters_do_not_count_for_heavy_artifacts(case, monkeypatch):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT},
                                              "collection": {"agent_collections": "auto"}})
    for trivial in (".", ".*", "^.*$"):
        with pytest.raises(collection.CollectionError, match="real filter"):
            collection.collect("Windows.NTFS.MFT", {"FileRegex": trivial}, vql=FakeVQL(), requested_by="agent",
                               sleep=lambda s: None)


def test_case_changes_are_validated_then_approved(two_cases_env, approve_all):
    cases.switch("alpha")
    cases.consume_switch()
    assert "start_time" in tools.update_case.invoke({"start_time": "yesterday"})
    assert "No case 'nope'" in tools.switch_case.invoke({"case_id": "nope"})
    assert "already active" in tools.switch_case.invoke({"case_id": "alpha"})
    assert "Case ID must be" in tools.create_case.invoke({"case_id": "../x", "name": "x"})
    assert "has no data" in tools.create_case.invoke({"case_id": "copy", "name": "x", "copy_data_from": "beta"})
    assert not os.path.exists(os.path.join(os.environ["DFIR_CASES_DIR"], "copy"))   # no half-made case
    assert approve_all == []                                                         # never asked
    assert "Switched to case 'beta'" in tools.switch_case.invoke({"case_id": "beta"})
    assert [r["kind"] for r in approve_all] == ["switch_case"]
    cases.consume_switch()


@pytest.fixture
def two_cases_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    saved = (case_config.path, dict(case_config.data), cases.case_db.case_dir)
    cases.create("alpha", "Alpha")
    cases.create("beta", "Beta")
    yield
    case_config.path, case_config.data = saved[0], saved[1]
    cases.case_db.open(saved[2])
    cases.consume_switch()


def test_cli_prompt_shows_what_the_agent_wants(monkeypatch, capsys):
    import builtins
    from copilot.agent import _confirm
    answers = iter(["y", ""])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(answers))
    request = {"kind": "retract_finding", "summary": "'coreupdater service' because: x", "details": {}}
    assert _confirm(request) is True
    assert _confirm(request) is False                     # Enter = No
    out = capsys.readouterr().out
    assert "The agent wants to retract a finding" in out and "'coreupdater service' because: x" in out
