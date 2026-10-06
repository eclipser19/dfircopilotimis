import json

import pytest

from copilot import collection
from copilot.collection import CollectionError, encode_params
from conftest import CLIENT, FakeVQL


def test_params_go_through_env_never_into_vql_text(case):
    vql = FakeVQL()
    nasty = "C:/it's ')\" ; SELECT * FROM execve()"
    collection.collect("Generic.Client.Info", {"Path": nasty, "Recurse": True}, vql=vql, sleep=lambda s: None)

    query, env = vql.calls[0]
    assert query == collection.SCHEDULE_VQL
    assert nasty not in query
    assert env["ClientId"] == CLIENT
    assert env["Artifact"] == "Generic.Client.Info"
    assert json.loads(env["Params"]) == {"Path": nasty, "Recurse": "Y"}


def test_encode_params_types():
    assert encode_params({"a": True, "b": False, "c": 5, "d": ["x"], "e": None}) == {
        "a": "Y", "b": "N", "c": "5", "d": '["x"]', "e": ""}


def test_finished_collection_is_ingested_once(case):
    vql = FakeVQL()
    first = collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    assert first["state"] == "FINISHED"
    assert first["new_rows_ingested"] == 1
    assert case.get_stats()["total_events"] == 1

    # Checking the same flow again must not ingest again.
    again = collection.check("F.TEST1", vql=FakeVQL())
    assert again["new_rows_ingested"] == 1
    assert case.get_stats()["total_events"] == 1


def test_recollecting_same_rows_does_not_duplicate(case):
    collection.collect("Generic.Client.Info", vql=FakeVQL(), sleep=lambda s: None)
    case.upsert_collection("F.TEST1", ingested=0)  # simulate a second, separate flow
    second = collection.check("F.TEST1", vql=FakeVQL())
    assert second["new_rows_ingested"] == 0
    assert case.get_stats()["total_events"] == 1


def test_running_collection_is_reported_not_called_empty(case):
    summary = collection.collect("Generic.Client.Info", vql=FakeVQL(states=("RUNNING",)),
                                 wait_seconds=0, sleep=lambda s: None)
    assert summary["state"] == "RUNNING"
    assert "new_rows_ingested" not in summary
    assert "check_collection" in summary["note"]
    assert case.get_stats()["total_events"] == 0

    later = collection.check("F.TEST1", vql=FakeVQL(states=("FINISHED",)))
    assert later["state"] == "FINISHED"
    assert later["new_rows_ingested"] == 1


def test_errored_collection_surfaces_error(case):
    summary = collection.collect("Generic.Client.Info", vql=FakeVQL(states=("ERROR",), flow_error="boom"),
                                 sleep=lambda s: None)
    assert summary["state"] == "ERROR"
    assert summary["error"] == "boom"


def test_hostname_comes_from_client_lookup(case):
    collection.collect("Generic.Client.Info", vql=FakeVQL(), sleep=lambda s: None)
    rows = case.query_timeline()
    assert rows and rows[0]["hostname"] == "WS01"


def test_schedule_without_flow_reports_log(case):
    with pytest.raises(CollectionError, match="artifact not found"):
        collection.schedule("Generic.Client.Info", vql=FakeVQL(schedule_fails=True))


def test_missing_client_id_refuses(case, monkeypatch):
    from copilot.case_config import case_config
    monkeypatch.setattr(case_config, "data", {})
    vql = FakeVQL()
    with pytest.raises(CollectionError, match="client_id"):
        collection.schedule("Generic.Client.Info", vql=vql)
    assert vql.calls == []


@pytest.mark.parametrize("artifact", [
    "Windows.System.PowerShell", "Windows.System.CmdShell", "Linux.Sys.BashShell",
    "Windows.Remediation.Quarantine", "Server.Utils.DeleteClient", "Some.Unlisted.Artifact",
])
def test_disallowed_artifacts_refused_before_any_call(case, artifact):
    vql = FakeVQL()
    with pytest.raises(CollectionError, match="not allowed"):
        collection.schedule(artifact, vql=vql)
    assert vql.calls == []


def test_unknown_flow_refused(case):
    with pytest.raises(CollectionError, match="not started by this case"):
        collection.check("F.SOMEONE_ELSES", vql=FakeVQL())


def test_auto_collect_reports_each_artifact_without_llm(case, monkeypatch):
    from copilot.agent import auto_collect
    from copilot.case_config import case_config
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT},
                                              "collect": ["Generic.Client.Info", "Windows.System.CmdShell"]})
    summaries = auto_collect(case_config, collect=lambda a: collection.collect(
        a, vql=FakeVQL(), sleep=lambda s: None))
    assert [s["state"] for s in summaries] == ["FINISHED", "NOT_STARTED"]
    assert "not allowed" in summaries[1]["error"]
