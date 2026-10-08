import json

import pytest

from copilot import collection
from copilot.collection import CollectionError, encode_params
from conftest import CLIENT, FakeVQL


def test_params_go_through_env_never_into_vql_text(case):
    vql = FakeVQL()
    nasty = "C:/it's ')\" ; SELECT * FROM execve()"
    collection.collect("Generic.Client.Info", {"Path": nasty, "Recurse": True}, vql=vql, sleep=lambda s: None)

    query, env = next(call for call in vql.calls if "collect_client" in call[0])
    assert query == collection.SCHEDULE_VQL.format(limits=", max_rows=50000")
    assert nasty not in query
    assert env["DfirClientId"] == CLIENT
    assert env["DfirArtifact"] == "Generic.Client.Info"
    assert json.loads(env["DfirSpec"]) == {"Generic.Client.Info": {"Path": nasty, "Recurse": "Y"}}


def test_no_params_still_sends_spec_for_the_artifact(case):
    vql = FakeVQL()
    collection.schedule("Generic.Client.Info", vql=vql)
    assert json.loads(vql.calls[0][1]["DfirSpec"]) == {"Generic.Client.Info": {}}


def test_progress_noise_stripped_from_errors(case):
    vql = FakeVQL(schedule_fails=True)
    vql_log = ("Starting query execution.\ncollect_client: Parameter refers to an unknown artifact\n"
               "Time 0: AgentQuery: Sending response part 0 15 B (1 rows).")
    vql.run_vql = lambda q, env=None, timeout=None: {"results": [], "log": vql_log}
    with pytest.raises(CollectionError) as e:
        collection.schedule("Generic.Client.Info", vql=vql)
    assert "unknown artifact" in str(e.value)
    assert "Starting query" not in str(e.value) and "Sending response" not in str(e.value)


def test_encode_params_types():
    assert encode_params({"a": True, "b": False, "c": 5, "d": ["x"], "e": None}) == {
        "a": "Y", "b": "N", "c": "5", "d": '["x"]', "e": ""}


def test_finished_collection_is_ingested_once(case):
    vql = FakeVQL()
    first = collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    assert first["state"] == "FINISHED"
    assert first["new_rows_ingested"] == 1
    assert case.get_stats()["total_records"] == 1

    # Checking the same flow again must not ingest again.
    again = collection.check("F.TEST1", vql=FakeVQL())
    assert again["new_rows_ingested"] == 1
    assert case.get_stats()["total_records"] == 1


def test_recollecting_same_rows_does_not_duplicate(case):
    collection.collect("Generic.Client.Info", vql=FakeVQL(), sleep=lambda s: None)
    case.upsert_collection("F.TEST1", ingested=0)  # simulate a second, separate flow
    second = collection.check("F.TEST1", vql=FakeVQL())
    assert second["new_rows_ingested"] == 0
    assert case.get_stats()["total_records"] == 1


def test_running_collection_is_reported_not_called_empty(case):
    summary = collection.collect("Generic.Client.Info", vql=FakeVQL(states=("RUNNING",)),
                                 wait_seconds=0, sleep=lambda s: None)
    assert summary["state"] == "RUNNING"
    assert "new_rows_ingested" not in summary
    assert "check_collection" in summary["note"]
    assert case.get_stats()["total_records"] == 0

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
    rows = case.search_events("WS01")["records"]
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
    summaries = auto_collect(case_config, collect=lambda a, p=None: collection.collect(
        a, vql=FakeVQL(), sleep=lambda s: None))
    assert [s["state"] for s in summaries] == ["FINISHED", "NOT_STARTED"]
    assert "not allowed" in summaries[1]["error"]


def test_vql_variables_cannot_shadow_builtins(case):
    """`Artifact` etc. are built-in VQL names; our variables must never reuse them."""
    vql = FakeVQL()
    collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    for query, env in vql.calls:
        assert env, query
        for key in env:
            assert key.startswith("Dfir"), (key, query)
            assert key in query, (key, query)


def test_waiting_and_in_progress_keep_waiting(case):
    vql = FakeVQL(states=("WAITING", "IN_PROGRESS", "IN_PROGRESS", "FINISHED"))
    summary = collection.collect("Generic.Client.Info", vql=vql, wait_seconds=60, sleep=lambda s: None)
    assert summary["state"] == "FINISHED"
    assert summary["new_rows_ingested"] == 1


def test_named_source_read_with_separate_source_argument(case):
    vql = FakeVQL()
    collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    source_calls = [env for q, env in vql.calls if "FROM source(" in q]
    assert source_calls == [{"DfirClientId": CLIENT, "DfirFlowId": "F.TEST1",
                             "DfirArtifact": "Generic.Client.Info", "DfirSource": "BasicInformation"}]


def test_reported_rows_that_cannot_be_read_are_not_marked_done(case):
    # flows() says 5 rows, source() returns none: must not be remembered as an empty result.
    vql = FakeVQL(rows={"Generic.Client.Info/BasicInformation": []}, reported_rows=5)
    summary = collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    assert summary["rows_collected_by_velociraptor"] == 5
    assert summary["rows_read"] == 0
    assert "copilot problem" in summary["note"]
    assert not case.get_collection("F.TEST1")["ingested"]

    # Once the rows are readable, the next check ingests them.
    retry = collection.check("F.TEST1", vql=FakeVQL())
    assert retry["new_rows_ingested"] == 1


def test_zero_rows_from_velociraptor_is_explained(case):
    vql = FakeVQL(rows={}, reported_rows=0)
    summary = collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    assert summary["rows_collected_by_velociraptor"] == 0
    assert "remapping" in summary["note"]
    assert case.get_collection("F.TEST1")["ingested"]


def test_rows_but_no_listed_sources_falls_back_to_artifact(case):
    vql = FakeVQL(rows={"Windows.System.TaskScheduler": [{"Name": "t"}]}, listed=[])
    summary = collection.collect("Windows.System.TaskScheduler", vql=vql, sleep=lambda s: None)
    assert summary["rows_read"] == 1


def test_empty_collection_shows_velociraptor_warnings(case):
    logs = [{"level": "INFO", "message": "Starting collection"},
            {"level": "DEFAULT", "message": "glob: Access is denied: C:\\Windows\\Prefetch"},
            {"level": "INFO", "message": "Collection is done"}]
    summary = collection.collect("Windows.Timeline.Prefetch", vql=FakeVQL(rows={}, reported_rows=0, flow_logs=logs),
                                 sleep=lambda s: None)
    assert summary["velociraptor_log"] == ["DEFAULT: glob: Access is denied: C:\\Windows\\Prefetch"]


def test_successful_collection_does_not_fetch_logs(case):
    vql = FakeVQL()
    collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    assert not any("flow_logs" in q for q, _ in vql.calls)


def test_live_only_artifact_refused_before_collecting(case):
    vql = FakeVQL()
    with pytest.raises(CollectionError, match="only works on a running system"):
        collection.collect("Windows.System.Services", vql=vql, sleep=lambda s: None)
    assert vql.calls == []


def test_disabled_plugin_in_flow_log_is_explained(case):
    # Artifacts not (yet) marked live-only in the knowledge base are still explained afterwards.
    logs = [{"level": "DEFAULT", "message": "Call to function lookupSID disabled"}]
    summary = collection.collect("Windows.System.TaskScheduler",
                                 vql=FakeVQL(rows={}, reported_rows=0, flow_logs=logs), sleep=lambda s: None)
    assert "lookupSID" in summary["note"] and "running system" in summary["note"]