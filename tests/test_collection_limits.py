import json

import pytest

from copilot import collection
from copilot.case_config import case_config
from copilot.collection import CollectionError
from conftest import CLIENT, FakeVQL

SCOPE = {"start_time": "2020-09-18T00:00:00Z", "end_time": "2020-09-20T00:00:00Z"}


def _spec(vql):
    return next(json.loads(env["DfirSpec"]) for q, env in vql.calls if "collect_client" in q)


def _config(monkeypatch, **collection_cfg):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT}, "scope": SCOPE,
                                              "collection": collection_cfg})


def test_time_window_fills_the_artifacts_own_date_params(case, monkeypatch):
    _config(monkeypatch)
    vql = FakeVQL(artifact_params=["EvtxGlob", "DateAfter", "DateBefore"])
    summary = collection.collect("Windows.EventLogs.EvtxHunter", {"IdRegex": "4624"}, vql=vql,
                                 sleep=lambda s: None)
    assert _spec(vql)["Windows.EventLogs.EvtxHunter"] == {
        "IdRegex": "4624", "DateAfter": SCOPE["start_time"], "DateBefore": SCOPE["end_time"]}
    assert summary["time_window_applied"] == {"DateAfter": SCOPE["start_time"], "DateBefore": SCOPE["end_time"]}


def test_time_window_respects_explicit_values_and_param_case(case, monkeypatch):
    _config(monkeypatch)
    vql = FakeVQL(artifact_params=["dateAfter", "dateBefore"])  # Prefetch-style lowercase
    collection.collect("Windows.Timeline.Prefetch", {"dateAfter": "2020-09-19T02:00:00Z"}, vql=vql,
                       sleep=lambda s: None)
    assert _spec(vql)["Windows.Timeline.Prefetch"] == {"dateAfter": "2020-09-19T02:00:00Z",
                                                       "dateBefore": SCOPE["end_time"]}


def test_no_window_when_artifact_has_no_date_params_or_disabled(case, monkeypatch):
    _config(monkeypatch)
    vql = FakeVQL(artifact_params=["Glob"])
    collection.collect("Windows.System.TaskScheduler", vql=vql, sleep=lambda s: None)
    assert _spec(vql)["Windows.System.TaskScheduler"] == {}

    _config(monkeypatch, apply_time_window=False)
    vql = FakeVQL(artifact_params=["DateAfter"])
    collection.collect("Windows.System.TaskScheduler", vql=vql, sleep=lambda s: None)
    assert _spec(vql)["Windows.System.TaskScheduler"] == {}


def test_row_limit_sent_to_velociraptor(case, monkeypatch):
    _config(monkeypatch, max_rows=1234)
    vql = FakeVQL()
    collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    assert any("max_rows=1234" in q for q, _ in vql.calls)


def test_older_velociraptor_without_max_rows_still_collects(case, monkeypatch):
    _config(monkeypatch)
    vql = FakeVQL(rejects_max_rows=True)
    summary = collection.collect("Generic.Client.Info", vql=vql, sleep=lambda s: None)
    assert summary["state"] == "FINISHED"


def test_ingest_stops_at_row_limit_and_flags_truncation(case, monkeypatch):
    _config(monkeypatch, max_rows=3)
    rows = {"Windows.System.TaskScheduler": [{"Name": f"svc{i}"} for i in range(10)]}
    summary = collection.collect("Windows.System.TaskScheduler", vql=FakeVQL(rows=rows), sleep=lambda s: None)
    assert summary["rows_read"] == 3
    assert summary["truncated"] is True
    assert "INCOMPLETE" in summary["note"]
    assert case.get_stats()["total_records"] == 3


def test_agent_heavy_artifact_needs_a_filter(case, monkeypatch):
    _config(monkeypatch, agent_collections="auto")
    vql = FakeVQL(artifact_params=["DateAfter", "DateBefore", "FileRegex"])
    with pytest.raises(CollectionError, match="millions of rows"):
        collection.collect("Windows.NTFS.MFT", vql=vql, requested_by="agent", sleep=lambda s: None)
    assert not any("collect_client" in q for q, _ in vql.calls)  # time window alone isn't a filter

    summary = collection.collect("Windows.NTFS.MFT", {"FileRegex": "coreupdater"}, vql=FakeVQL(),
                                 requested_by="agent", sleep=lambda s: None)
    assert summary["state"] == "FINISHED"


def test_agent_parameter_names_must_be_the_artifacts_own(case, monkeypatch):
    _config(monkeypatch, agent_collections="auto")
    declared = [{"name": "PathGlob", "default": "C:/Users/**", "description": "Files to check for streams"},
                {"name": "DateAfter"}]
    vql = FakeVQL(artifact_params=declared)
    guessed = {"TargetGlob": "C:/Windows/System32/x.exe", "AdsNameGlob": "Zone.Identifier"}
    with pytest.raises(CollectionError) as e:
        collection.collect("Windows.NTFS.ADSHunter", guessed, vql=vql, requested_by="agent", sleep=lambda s: None)
    assert "no parameter 'TargetGlob', 'AdsNameGlob'" in str(e.value) and "would ignore" in str(e.value)
    assert "PathGlob (default 'C:/Users/**'): Files to check for streams; DateAfter" in str(e.value)
    assert not any("collect_client" in q for q, _ in vql.calls)

    vql = FakeVQL(artifact_params=declared)            # letter case is corrected
    collection.collect("Windows.NTFS.ADSHunter", {"pathglob": "C:/Windows/System32/x.exe"}, vql=vql,
                       requested_by="agent", sleep=lambda s: None)
    assert _spec(vql)["Windows.NTFS.ADSHunter"] == {"PathGlob": "C:/Windows/System32/x.exe",
                                                    "DateAfter": SCOPE["start_time"]}


def test_parameter_names_are_not_checked_when_they_cannot_be_looked_up(case, monkeypatch):
    _config(monkeypatch, agent_collections="auto")
    vql = FakeVQL()                                    # artifact_definitions returns no parameters
    collection.collect("Windows.System.TaskScheduler", {"Anything": "1"}, vql=vql, requested_by="agent",
                       sleep=lambda s: None)
    assert _spec(vql)["Windows.System.TaskScheduler"] == {"Anything": "1"}


def test_investigator_collections_skip_agent_rules(case, monkeypatch):
    _config(monkeypatch, agent_collections="off")
    summary = collection.collect("Windows.NTFS.MFT", vql=FakeVQL(), sleep=lambda s: None)
    assert summary["state"] == "FINISHED"


def test_agent_collections_off(case, monkeypatch):
    _config(monkeypatch, agent_collections="off")
    with pytest.raises(CollectionError, match="does not allow the agent to collect"):
        collection.collect("Windows.System.TaskScheduler", vql=FakeVQL(), requested_by="agent", sleep=lambda s: None)


def test_agent_collections_need_approval(case, monkeypatch):
    from copilot import approvals
    _config(monkeypatch)  # default: confirm
    asked = []
    monkeypatch.setattr(approvals, "ASK", lambda request: asked.append(request) or False)
    vql = FakeVQL()
    monkeypatch.setattr(collection, "get_vql", lambda: vql)
    with pytest.raises(CollectionError, match="declined"):
        collection.collect("Windows.System.TaskScheduler", vql=vql, requested_by="agent", sleep=lambda s: None)
    assert [(r["kind"], r["details"]["artifact"]) for r in asked] == [("collect", "Windows.System.TaskScheduler")]
    assert not any("collect_client" in q for q, _ in vql.calls)

    monkeypatch.setattr(approvals, "ASK", lambda request: True)
    monkeypatch.setattr(collection, "get_vql", lambda: FakeVQL())
    summary = collection.collect("Windows.System.TaskScheduler", vql=FakeVQL(), requested_by="agent",
                                 sleep=lambda s: None)
    assert summary["state"] == "FINISHED"


def test_no_approval_channel_refuses(case, monkeypatch):
    _config(monkeypatch)
    from copilot import approvals
    monkeypatch.setattr(approvals, "ASK", None)
    with pytest.raises(CollectionError, match="approval"):
        collection.collect("Windows.System.TaskScheduler", vql=FakeVQL(), requested_by="agent", sleep=lambda s: None)


def test_a_short_time_window_counts_as_a_filter(case, monkeypatch):
    _config(monkeypatch, agent_collections="auto")
    narrow = {"DateAfter": "2020-09-19T03:45:00Z", "DateBefore": "2020-09-19T03:48:00Z"}
    summary = collection.collect("Windows.Forensics.Usn", narrow, vql=FakeVQL(artifact_params=["DateAfter", "DateBefore"]),
                                 requested_by="agent", sleep=lambda s: None)
    assert summary["state"] == "FINISHED"
    wide = {"DateAfter": "2020-09-19T00:00:00Z", "DateBefore": "2020-09-19T03:00:00Z"}
    with pytest.raises(CollectionError, match="at most 60 minutes"):
        collection.collect("Windows.Forensics.Usn", wide, vql=FakeVQL(artifact_params=["DateAfter", "DateBefore"]),
                           requested_by="agent", sleep=lambda s: None)


def test_empty_result_note_uses_what_the_case_collected_before(case, monkeypatch):
    _config(monkeypatch)
    flow_ids = iter(range(100))

    class Flows(FakeVQL):                       # a new flow ID per collection, like Velociraptor
        def run_vql(self, query, env=None, timeout=None):
            res = super().run_vql(query, env, timeout)
            if "collect_client" in query and res["results"]:
                res["results"][0]["flow"]["flow_id"] = f"F.T{next(flow_ids)}"
            return res

    def nothing():
        return Flows(rows={"Windows.NTFS.MFT": []}, reported_rows=0, listed=[])

    first = collection.collect("Windows.NTFS.MFT", {"FileRegex": "x"}, vql=nothing(), sleep=lambda s: None)
    assert "did not resolve through the remapping" in first["note"]          # nothing has worked yet: maybe
    collection.collect("Windows.Timeline.Prefetch", vql=Flows(rows={"Windows.Timeline.Prefetch": [{"Name": "A.EXE"}]}),
                       sleep=lambda s: None)
    second = collection.collect("Windows.NTFS.MFT", {"FileRegex": "y"}, vql=nothing(), sleep=lambda s: None)
    assert "The image is readable" in second["note"] and "remapping" not in second["note"]
    collection.collect("Windows.NTFS.MFT", {"FileRegex": "z"},
                       vql=Flows(rows={"Windows.NTFS.MFT": [{"FileName": "z.txt"}]}), sleep=lambda s: None)
    third = collection.collect("Windows.NTFS.MFT", {"FileRegex": "^loot\\.zip$"}, vql=nothing(), sleep=lambda s: None)
    assert "This artifact works on this image" in third["note"] and "loot" in third["note"]
    assert "Do not blame the disk mapping" in third["note"]
