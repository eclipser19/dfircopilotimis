from datetime import datetime, timezone

import pytest

from copilot.normalize import (describe, event_type_for, extract_entities, extract_timestamps,
                               normalize_bound, parse_timestamp)

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)
TEN_UTC = "2026-10-05T10:00:00.000000Z"


@pytest.mark.parametrize("value,field", [
    ("2026-10-05T10:00:00Z", "EventTime"),
    ("2026-10-05T10:00:00.000000000+00:00", "x"),
    ("2026-10-05T03:00:00-07:00", "Created0x10"),
    ("2026-10-05 12:00:00+0200", "x"),
    (1791194400, "SystemTime"),
    (1791194400.0, "TimeCreated"),
    ("1791194400", "LastRunTime"),
    (1791194400000, "timestamp_ms"),
    (134356680000000000, "LastWriteTime"),  # FILETIME
])
def test_timestamp_formats_normalize_to_same_utc(value, field):
    ts = parse_timestamp(value, field, NOW)
    assert ts is not None, value
    assert ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ") == TEN_UTC


@pytest.mark.parametrize("value,field", [
    ("1601-01-01T00:00:00Z", "Created"),      # zero FILETIME
    ("1970-01-01T00:00:00Z", "Mtime"),        # zero epoch
    ("2099-01-01T00:00:00Z", "Mtime"),        # far future
    (1791194400, "Size"),                     # number in a non-time field
    (True, "Time"),
    ("not a date", "Time"),
    ("2026-10-05", "Time"),                   # date only: ambiguous, skipped
])
def test_non_timestamps_rejected(value, field):
    assert parse_timestamp(value, field, NOW) is None


def test_one_event_per_distinct_time_with_field_names():
    row = {
        "Created0x10": "2026-10-05T10:00:00Z",
        "Modified0x10": "2026-10-05T10:00:00Z",
        "Created0x30": "2026-10-04T09:00:00Z",
        "_ts": 1791194400,  # Velociraptor bookkeeping: collection time, not evidence
        "System": {"TimeCreated": {"SystemTime": 1791198000}},
        "LastRunTimes": ["2026-10-05T11:00:00Z", "2026-10-05T12:00:00Z"],
    }
    stamps = extract_timestamps(row, NOW)
    assert stamps == [
        ("2026-10-04T09:00:00.000000Z", "Created0x30"),
        ("2026-10-05T10:00:00.000000Z", "Created0x10, Modified0x10"),
        ("2026-10-05T11:00:00.000000Z", "System.TimeCreated.SystemTime, LastRunTimes[0]"),
        ("2026-10-05T12:00:00.000000Z", "LastRunTimes[1]"),
    ]


def test_entities_from_nested_fields():
    row = {"EventID": 4624, "EventData": {"TargetUserName": "jdoe", "IpAddress": "10.0.0.5",
                                         "ProcessName": "C:\\Windows\\System32\\lsass.exe"},
           "OSPath": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"}
    assert extract_entities(row) == {
        "event_id": "4624", "user": "jdoe", "ip": "10.0.0.5",
        "process": "C:\\Windows\\System32\\lsass.exe",
        "path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    }


def test_description_prefers_message_and_adds_entities():
    row = {"Message": "An account was\n successfully logged on.", "EventData": {"TargetUserName": "jdoe"}}
    text = describe(row, extract_entities(row))
    assert text == "user=jdoe; An account was successfully logged on."


def test_description_puts_identifying_fields_before_boilerplate():
    row = {"EventID": 4624, "Message": "An account was successfully logged on. Subject: Security ID: S-1-0-0 ...",
           "EventData": {"LogonType": 10, "TargetUserName": "Administrator", "IpAddress": "10.42.85.10"},
           "OSPath": "C:/Windows/System32/winevt/Logs/Security.evtx"}
    text = describe(row, extract_entities(row))
    assert text.startswith("event_id=4624; LogonType=10; user=Administrator; ip=10.42.85.10; An account")
    assert text.endswith("path=C:/Windows/System32/winevt/Logs/Security.evtx")


@pytest.mark.parametrize("source,expected", [
    ("Windows.System.TaskScheduler/Analysis", "persistence"),
    ("Windows.EventLogs.RDPAuth", "authentication"),
    ("Windows.EventLogs.EvtxHunter", "event_log"),
    ("Windows.EventLogs.PowershellScriptblock", "script_execution"),
    ("Windows.System.Powershell.PSReadline", "command_history"),
    ("Windows.Forensics.Lnk", "user_activity"),
    ("Windows.Registry.RecentDocs", "user_activity"),
    ("Windows.Forensics.SRUM/Execution Stats", "execution"),
    ("Windows.Timeline.Prefetch", "execution"),
    ("Windows.NTFS.MFT", "filesystem"),
    ("Linux.Syslog.SSHLogin", "authentication"),
    ("Linux.Forensics.Journal", "event_log"),
    ("Generic.Client.Info/BasicInformation", "system_info"),
    ("Windows.Forensics.Usn", "filesystem"),
    ("Windows.Sys.StartupItems", "persistence"),
    ("Custom.Unknown", "other"),
])
def test_event_types(source, expected):
    assert event_type_for(source) == expected


def test_bounds_normalized_and_validated():
    assert normalize_bound("2026-10-05T10:00:00Z") == TEN_UTC
    assert normalize_bound("2026-10-05T12:00:00+02:00") == TEN_UTC
    assert normalize_bound(None) is None
    with pytest.raises(ValueError):
        normalize_bound("yesterday")


def test_memory_descriptions_name_unreadable_values():
    from copilot.normalize import normalize_row

    def described(row, source):
        return normalize_row(row, source)["description"]

    net = {"Proto": "TCPv4", "LocalAddr": "10.42.85.115", "LocalPort": 49679, "ForeignAddr": "203.78.103.109",
           "ForeignPort": 443, "State": "ESTABLISHED", "PID": None, "Owner": None}
    assert described(net, "Memory.windows.netscan.NetScan") == \
        "TCPv4 10.42.85.115:49679 -> 203.78.103.109:443 ESTABLISHED; owning process not readable"
    assert described(dict(net, PID=3316, Owner="powershell.exe"), "Memory.windows.netscan.NetScan").endswith(
        "ESTABLISHED owner powershell.exe PID 3316")
    assert described({"PID": 3316, "Process": "powershell.exe", "Args": None}, "Memory.windows.cmdline.CmdLine") == \
        "powershell.exe PID 3316: command line not readable from memory (paged out or exited)"
    assert described({"Name": "coreupdater", "State": "SERVICE_STOPPED", "Binary": None,
                      "Binary (Registry)": "C:\\Windows\\System32\\coreupdater.exe"},
                     "Memory.windows.svcscan.SvcScan") == \
        "service coreupdater SERVICE_STOPPED registry binary C:\\Windows\\System32\\coreupdater.exe"


def test_stored_descriptions_are_rebuilt_when_the_normalizer_improves(tmp_path):
    from copilot.database import CaseDatabase
    db = CaseDatabase(str(tmp_path))
    db.ingest_artifact_results([{"PID": 3316, "Process": "powershell.exe", "Args": None}],
                               "Memory.windows.cmdline.CmdLine", "x", "memory:x")
    db.conn.execute("UPDATE records SET description = 'powershell.exe PID 3316:', process = NULL")
    db.conn.execute("DELETE FROM meta WHERE key = 'normalizer'")             # stored by an older version
    db.conn.commit()
    db.conn.close()
    db = CaseDatabase(str(tmp_path))
    row = db.conn.execute("SELECT description, process FROM records").fetchone()
    assert row["description"].endswith("command line not readable from memory (paged out or exited)")
    assert row["process"] == "powershell.exe"
    db.conn.execute("UPDATE records SET description = 'kept'")
    db.conn.commit()
    db.conn.close()
    assert CaseDatabase(str(tmp_path)).conn.execute("SELECT description FROM records").fetchone()[0] == "kept"


def test_web_log_line_time_is_converted_to_utc():
    line = '10.0.0.5 - - [10/Oct/2023:13:55:36 -0700] "GET /index.php?id=2 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    found = extract_timestamps({"Line": line, "OSPath": "C:\\web\\logs\\access.log"})
    assert [ts for ts, _ in found] == ["2023-10-10T20:55:36.000000Z"]
