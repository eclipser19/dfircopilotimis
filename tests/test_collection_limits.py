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
    collection.collect("Windows.System.Services", vql=vql, sleep=lambda s: None)
    assert _spec(vql)["Windows.System.Services"] == {}

    _config(monkeypatch, apply_time_window=False)
    vql = FakeVQL(artifact_params=["DateAfter"])
    collection.collect("Windows.System.Services", vql=vql, sleep=lambda s: None)
    assert _spec(vql)["Windows.System.Services"] == {}


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
    rows = {"Windows.System.Services": [{"Name": f"svc{i}"} for i in range(10)]}
    summary = collection.collect("Windows.System.Services", vql=FakeVQL(rows=rows), sleep=lambda s: None)
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


def test_investigator_collections_skip_agent_rules(case, monkeypatch):
    _config(monkeypatch, agent_collections="off")
    summary = collection.collect("Windows.NTFS.MFT", vql=FakeVQL(), sleep=lambda s: None)
    assert summary["state"] == "FINISHED"


def test_agent_collections_off(case, monkeypatch):
    _config(monkeypatch, agent_collections="off")
    with pytest.raises(CollectionError, match="disabled agent collections"):
        collection.collect("Windows.System.Services", vql=FakeVQL(), requested_by="agent", sleep=lambda s: None)


def test_agent_collections_need_approval(case, monkeypatch):
    _config(monkeypatch)  # default: confirm
    asked = []
    monkeypatch.setattr(collection, "CONFIRM", lambda a, p: asked.append((a, p)) or False)
    vql = FakeVQL()
    with pytest.raises(CollectionError, match="declined"):
        collection.collect("Windows.System.Services", vql=vql, requested_by="agent", sleep=lambda s: None)
    assert asked == [("Windows.System.Services", {})]
    assert not any("collect_client" in q for q, _ in vql.calls)

    monkeypatch.setattr(collection, "CONFIRM", lambda a, p: True)
    summary = collection.collect("Windows.System.Services", vql=FakeVQL(), requested_by="agent",
                                 sleep=lambda s: None)
    assert summary["state"] == "FINISHED"


def test_no_approval_channel_refuses(case, monkeypatch):
    _config(monkeypatch)
    monkeypatch.setattr(collection, "CONFIRM", None)
    with pytest.raises(CollectionError, match="approval"):
        collection.collect("Windows.System.Services", vql=FakeVQL(), requested_by="agent", sleep=lambda s: None)
