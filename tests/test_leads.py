"""Leads computed from collected data without the model: logon sources, account changes, services, tasks."""
import json

from copilot import leads, tools


def _logon(event_id, time, user, ip, workstation="WS1", logon_type=3, logon_id="1001", record=None):
    data = {"TargetUserName": user, "IpAddress": ip, "WorkstationName": workstation, "LogonType": logon_type,
            "TargetLogonId": logon_id, "SubjectUserName": "-"}
    return {"EventTime": time, "EventID": event_id, "Channel": "Security", "EventRecordID": record or hash(time) % 10**6,
            "EventData": data, "Message": "An account ..."}


def _seed(case):
    guessing = [_logon(4625, f"2024-02-05T10:{m:02d}:00Z", "Administrator", "198.51.100.9", "ATTACKER") for m in range(10, 50)]
    rows = guessing + [
        _logon(4624, "2024-02-05T10:55:56Z", "Administrator", "198.51.100.9", "ATTACKER", 3, "654401398"),
        _logon(4624, "2024-02-05T08:52:02Z", "Administrator", "203.0.113.5", "ADMIN-HOME", 10, "643091211"),
        _logon(4624, "2024-02-05T09:00:00Z", "jdoe", "10.0.0.5", "WS7", 3, "5"),
    ]
    case.ingest_artifact_results(rows, "Windows.EventLogs.EvtxHunter", client_id="C.1")
    # The same success collected again by another artifact is not a second logon.
    case.ingest_artifact_results([{**rows[-3], "Description": "copy"}], "Windows.EventLogs.RDPAuth", client_id="C.1")
    case.ingest_artifact_results([
        {"EventTime": "2024-02-05T23:02:00Z", "EventID": 4720, "Channel": "Security",
         "EventData": {"TargetUserName": "svc-new", "SubjectUserName": "Administrator", "SubjectLogonId": "77"}},
        {"EventTime": "2024-02-05T23:24:35Z", "EventID": 4728, "Channel": "Security",
         "EventData": {"TargetUserName": "Domain Admins", "MemberSid": "S-1-5-21-9-2611",
                       "SubjectUserName": "Administrator", "SubjectLogonId": "77"}},
        {"EventTime": "2024-02-05T23:42:42Z", "EventID": 7045, "Channel": "System", "Username": "svc-new",
         "EventData": {"ServiceName": "updater", "ImagePath": "C:\\Users\\svc-new\\AppData\\up.exe", "StartType": "auto"}},
        {"EventTime": "2024-02-06T01:00:00Z", "EventID": 1102, "Channel": "Security", "Message": "The audit log was cleared."},
        {"EventTime": "2024-02-06T01:00:01Z", "EventID": 1102, "Channel": "Microsoft-Windows-TerminalServices-RDPClient/Operational",
         "Message": "not a log clearing"},
    ], "Windows.EventLogs.EvtxHunter", client_id="C.1")
    case.ingest_artifact_results([
        {"OSPath": "C:\\Windows\\System32\\Tasks\\backup", "TaskName": "\\backup", "Command": "c:\\users\\svc-new\\tools\\psexec.exe",
         "Arguments": "\\\\host1 -u svc-new -p pw x.exe", "UserId": "svc-new", "LogonType": "Password",
         "RegistrationTime": "2024-02-06T21:49:21Z"},
        {"OSPath": "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
         "TaskName": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "Command": "%windir%\\system32\\defrag.exe",
         "UserId": "SYSTEM", "LogonType": "ServiceAccount"},
    ], "Windows.System.TaskScheduler/Analysis", client_id="C.1")
    case.ingest_artifact_results([
        {"DownloadedFilePath": f"C:\\Users\\svc-new\\Downloads\\Suite\\tool{i}.exe", "Mtime": f"2024-02-05T23:14:3{i}Z",
         "HostUrl": None, "ReferrerUrl": "C:\\Users\\svc-new\\Downloads\\Suite.zip", "ZoneId": "3"} for i in range(4)
    ], "Windows.Analysis.EvidenceOfDownload", client_id="C.1")
    case.ingest_artifact_results([
        {"FullPath": "c:\\users\\svc-new\\desktop\\payload.exe", "SHA1": "ab" * 20, "Timestamp": "2024-02-07T21:00:10Z"},
        {"FullPath": "c:\\program files\\vendor\\app.exe", "SHA1": "cd" * 20, "Timestamp": "2024-02-07T21:00:10Z"},
    ], "Windows.Forensics.Amcache/InventoryApplicationFile", client_id="C.1")


def test_logon_sources_put_guessing_that_worked_first(case):
    _seed(case)
    res = leads.logon_sources(case)
    first = res["sources"][0]
    assert first["ip"] == "198.51.100.9" and first["scope"] == "external"
    assert first["failures"] == 40 and first["successes"] == 1 and first["success_after_failures"]
    assert first["first_success"]["logon_id"] == "654401398" and first["first_success"]["timestamp_utc"].startswith("2024-02-05T10:55:56")
    assert first["workstations"] == {"ATTACKER": 41} and first["failed_accounts"] == {"Administrator": 40}
    assert [s["ip"] for s in res["sources"]] == ["198.51.100.9", "203.0.113.5", "10.0.0.5"]
    assert res["sources"][2]["scope"] == "internal"
    only = leads.logon_sources(case, account="jdoe")["sources"]
    assert [s["ip"] for s in only] == ["10.0.0.5"]


def test_failures_without_an_address_are_kept_by_workstation_name(case):
    # RDP with NLA: 4625 with no source address, only the client's name; the success names both.
    rows = [_logon(4625, f"2024-02-05T02:{m:02d}:00Z", "Administrator", "-", "ATTACKER", record=m) for m in range(19, 21)]
    rows.append(_logon(4624, "2024-02-05T02:21:47Z", "Administrator", "198.51.100.9", "ATTACKER", 3, "77", record=99))
    rows.append(_logon(4624, "2024-02-05T03:00:00Z", "svc", "-", "SRV01", 5, "88", record=100))   # local: not a source
    case.ingest_artifact_results(rows, "Windows.EventLogs.EvtxHunter", client_id="C.1")
    sources = {s["ip"]: s for s in leads.logon_sources(case)["sources"]}
    assert set(sources) == {"198.51.100.9", "(no address) ATTACKER"}
    nla = sources["(no address) ATTACKER"]
    assert nla["failures"] == 2 and nla["scope"] == "no address recorded" and nla["workstations"] == {"ATTACKER": 2}
    assert sources["198.51.100.9"]["workstations"] == {"ATTACKER": 1}


def test_leads_name_account_changes_services_tasks_and_downloads(case):
    _seed(case)
    out = leads.leads(case)
    changes = out["account_and_group_changes"]
    assert [c["event"] for c in changes] == ["4720 account created", "4728 added to a global group"]
    assert changes[1]["group"] == "Domain Admins" and changes[1]["by_logon_id"] == "77"
    assert out["services_installed"][0]["service"] == "updater" and "user-writable" in out["services_installed"][0]["look"]
    assert [t["task"] for t in out["scheduled_tasks_to_check"]] == ["\\backup"]       # the OS's own tasks are left out
    assert "-u svc-new -p pw" in out["scheduled_tasks_to_check"][0]["command"]
    assert [e["event"] for e in out["log_clearing_and_defender"]] == ["1102 Security log cleared"]
    assert out["downloads_by_origin"][0]["files"] == 4
    assert [p["path"] for p in out["programs_in_user_folders"]] == ["c:\\users\\svc-new\\desktop\\payload.exe"]


def test_case_summary_carries_the_leads_and_logon_summary_filters(case):
    _seed(case)
    summary = json.loads(tools.case_summary.invoke({}))
    assert summary["leads"]["logon_sources"][0]["ip"] == "198.51.100.9"
    out = json.loads(tools.logon_summary.invoke({"ip": "203.0.113.5"}))
    assert [s["ip"] for s in out["sources"]] == ["203.0.113.5"]
    assert out["sources"][0]["workstations"] == {"ADMIN-HOME": 1}
    assert "No logon events" in tools.logon_summary.invoke({"ip": "192.0.2.1"})


def test_web_searches_are_decoded_from_history_urls_per_user_and_browser(case):
    chrome = [{"User": "tim", "visit_time": "2020-04-09T20:36:29Z", "title": "x - Google Search",
               "visited_url": "https://www.google.com/search?q=hhoww+ddoo+i+fiirre&oq=hh"},
              {"User": "tim", "visit_time": "2020-04-09T20:36:40Z", "title": "x - Google Search",
               "visited_url": "https://www.google.com/search?q=HHOWW+ddoo+i+fiirre&start=10"},
              {"User": "tim", "visit_time": "2020-04-09T20:37:00Z", "visited_url": "https://www.google.com/url?q=https://a.example"},
              {"User": "jim", "visit_time": "2020-04-12T04:39:33Z", "title": "How To Hack - YouTube",
               "visited_url": "https://www.youtube.com/watch?v=abc123&t=4s"}]
    firefox = [{"User": "tim", "visit_time": "2020-04-09T20:45:07Z", "url_visited": "https://duckduckgo.com/?q=is+it+ok&t=ffab"}]
    case.ingest_artifact_results(chrome, "Windows.Applications.Chrome.History", "H", "C.1")
    case.ingest_artifact_results(firefox, "Windows.Applications.Firefox.History", "H", "C.1")
    out = leads.leads(case)
    searches = [(s["words"], s["user"], s["browser"], s["visits"]) for s in out["web_searches"]]
    assert searches == [("hhoww ddoo i fiirre", "tim", "Chrome", 2), ("is it ok", "tim", "Firefox", 1)]
    assert out["web_searches"][0]["engine"] == "Google" and out["web_searches"][0]["evidence_id"]
    [video] = out["youtube_videos_opened"]
    assert (video["title"], video["video"], video["user"]) == ("How To Hack", "abc123", "jim")


def _intrusion(case):
    """An RDP intrusion, as the triage and the code's own checks would collect it."""
    events = [
        _logon(4624, "2020-09-19T01:00:00Z", "Administrator", "10.42.85.115", "DESKTOP-1", 10, "0x10"),   # the admin
        _logon(4624, "2020-09-19T02:21:48Z", "Administrator", "194.61.24.102", "kali", 10, "0x510986"),
        _logon(4624, "2020-09-19T02:21:49Z", "Administrator", "194.61.24.102", "kali", 10, "5310900"),  # its twin
        {"EventTime": "2020-09-19T02:23:10Z", "EventID": 4688, "Channel": "Security",
         "EventData": {"NewProcessName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami",
                       "SubjectUserName": "Administrator", "SubjectLogonId": "5310854"}},
        {"EventTime": "2020-09-19T02:27:49Z", "EventID": 7045, "Channel": "System",
         "EventData": {"ServiceName": "coreupdater", "ImagePath": "C:\\Windows\\System32\\coreupdater.exe"}},
        {"EventTime": "2020-09-19T02:57:40Z", "EventID": 4634, "Channel": "Security",
         "EventData": {"TargetUserName": "Administrator", "TargetLogonId": "0x510986", "LogonType": 10}},
    ]
    case.ingest_artifact_results(events, "Windows.EventLogs.EvtxHunter", client_id="C.1")
    case.ingest_artifact_results([{"event_time": "2020-09-19T02:24:50Z", "file_name": "COREUPDATER.EXE",
                                   "prefetch_ctime": "2020-09-01T00:00:00Z",
                                   "source": "C:\\Windows\\Prefetch\\COREUPDATER.EXE-1.pf", "prefetch_count": 1}],
                                 "Windows.Timeline.Prefetch", client_id="C.1")
    case.ingest_artifact_results([
        {"Timestamp": "2020-09-19T02:32:39Z", "Filename": "Secret.zip", "OSPath": "C:\\FileShare\\Secret.zip",
         "Reason": ["FILE_CREATE"]},
        {"Timestamp": "2020-09-19T02:38:00Z", "Filename": "Beth_Secret.txt",
         "OSPath": "C:\\FileShare\\Secret\\Beth_Secret.txt", "Reason": ["BASIC_INFO_CHANGE"]},
        {"Timestamp": "2020-09-19T02:40:00Z", "Filename": "SRUDB.dat", "OSPath": "C:\\Windows\\System32\\sru\\SRUDB.dat",
         "Reason": ["BASIC_INFO_CHANGE"]}], "Windows.Forensics.Usn", client_id="C.1")
    case.ingest_artifact_results([{"SourceFile": {"OSPath": "C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\"
                                                            "Windows\\Recent\\Szechuan Sauce.lnk",
                                                  "Mtime": "2020-09-19T02:32:21Z"},
                                   "LinkTarget": {"LinkTarget": "C:\\FileShare\\Secret\\Szechuan Sauce.txt"}}],
                                 "Windows.Forensics.Lnk", client_id="C.1")
    case.ingest_artifact_results([
        {"OSPath": "\\\\.\\C:\\FileShare\\Secret\\Beth_Secret.txt", "FileName": "Beth_Secret.txt",
         "Created0x10": "2020-08-01T00:00:00Z", "Created0x30": "2020-09-18T21:39:04.5Z",
         "LastRecordChange0x10": "2020-09-19T02:38:00.25Z", "SI_Lt_FN": True, "USecZeros": True, "IsDir": False},
        {"OSPath": "\\\\.\\C:\\Windows\\System32\\x.dll", "FileName": "x.dll", "SI_Lt_FN": True,
         "Created0x10": "2020-08-01T00:00:00Z"}], "Windows.NTFS.MFT", client_id="C.1")


def test_sessions_tie_what_happened_to_the_logon_that_did_it(case):
    _intrusion(case)
    found = {s["ip"]: s for s in leads.sessions(case)}
    rdp = found["194.61.24.102"]
    assert set(rdp["logon_ids"]) == {"5310854", "5310900"} and rdp["logon_types"] == ["RDP"]   # one session
    assert rdp["scope"] == "external" and rdp["logoff"]["timestamp_utc"].startswith("2020-09-19T02:57:40")
    assert [i["what"][:4] for i in rdp["by_logon_id"]] == ["4688"]                 # proven by its logon ID
    window = rdp["same_time_window"]
    assert any("coreupdater" in i["what"] for i in window["persistence"])            # the service, by time
    assert [i["time_field"] for i in window["programs_run"]] == ["event_time"]      # a run, not the .pf's times
    assert {i["what"].split(";")[-1].strip() for i in window["files"] if "Secret.zip" in i["what"]}
    admin = found["10.42.85.115"]
    assert admin["by_logon_id"] == [] and admin["logoff"].startswith("none recorded")
    shown = leads.leads(case)["sessions_to_check"]
    assert shown[0]["ip"] == "10.42.85.115" and shown[1]["ip"] == "194.61.24.102"   # oldest first
    assert shown[1]["by_logon_id"]["count"] == 1 and "same_time_window" in shown[1]
    full = json.loads(tools.session_activity.invoke({"logon_id": "0x510986"}))
    assert [s["ip"] for s in full] == ["194.61.24.102"]


def test_hand_set_timestamps_and_odd_autostarts_are_leads(case):
    _intrusion(case)
    [top] = leads.timestamp_changes(case)                       # the MFT and USN records of one file
    assert top["path"].endswith("\\FileShare\\Secret\\Beth_Secret.txt")
    assert top["signs"] == ["$SI earlier than $FN", "whole-second $SI times",
                            "USN BASIC_INFO_CHANGE without a data change"] and top["usn_evidence_id"]
    assert top["timestamp_utc"].startswith("2020-09-19T02:38:00")                    # when the entry changed
    case.ingest_artifact_results([
        {"Name": "updater", "OSPath": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater",
         "Details": "C:\\Users\\Public\\upd.exe -s", "Enabled": "enabled"},
        {"Name": "OneDrive", "OSPath": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
         "Details": "\"C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"},
        {"Name": "SecurityHealth", "OSPath": "HKLM\\...\\Run\\SecurityHealth",
         "Details": "C:\\Windows\\System32\\SecurityHealthSystray.exe"},
        {"Name": "helper", "OSPath": "HKLM\\...\\Run\\helper",
         "Details": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -enc AAA"},
    ], "Windows.Sys.StartupItems", client_id="C.1")
    assert {a["name"]: a["look"] for a in leads.autostart(case)} == {"updater": "user-writable path",
                                                                     "helper": "scripting/admin tool"}


def test_the_code_reads_the_mft_records_of_the_files_the_sessions_touched(case, monkeypatch):
    from copilot import checks, collection
    from conftest import FakeVQL
    _intrusion(case)
    assert checks.touched_files(case) == ["Szechuan Sauce.txt", "Secret.zip", "Beth_Secret.txt"]   # in time order
    vql = FakeVQL(artifact_params=["FileRegex", "DateAfter", "DateBefore"])
    monkeypatch.setattr(collection, "get_vql", lambda: vql)
    monkeypatch.setattr(collection, "time", __import__("types").SimpleNamespace(monotonic=lambda: 0, sleep=lambda s: None))
    note = checks.before_investigation()
    sent = json.loads(next(env["DfirSpec"] for q, env in vql.calls if "collect_client" in q))["Windows.NTFS.MFT"]
    assert sent["FileRegex"] == "(?i)^(Szechuan Sauce\\.txt|Secret\\.zip|Beth_Secret\\.txt)$"
    assert sent["DateAfter"] == "" and "timestamps_set_by_hand" in note


def test_credentials_used_for_other_hosts_and_shortcuts_to_them_are_leads(case):
    def explicit(time, server, address, process="C:\\Users\\svc\\Downloads\\PsExec.exe"):
        return {"EventTime": time, "EventID": 4648, "Channel": "Security", "EventRecordID": hash(time) % 10**6,
                "EventData": {"SubjectUserName": "svc", "SubjectLogonId": "0x77", "TargetUserName": "svc",
                              "TargetServerName": server, "IpAddress": address, "ProcessName": process}}
    case.ingest_artifact_results([explicit("2024-02-05T23:19:01Z", "Desktop-001", "10.0.24.1"),
                                  explicit("2024-02-05T23:20:00Z", "Desktop-001", "10.0.24.1"),
                                  explicit("2024-02-05T23:22:19Z", "desktop-005", "10.0.24.9"),
                                  explicit("2024-02-05T23:30:00Z", "localhost", "127.0.0.1", "C:\\Windows\\System32\\svchost.exe"),
                                  {**explicit("2024-02-05T01:00:00Z", "dc01.corp.example", "10.0.0.1",
                                              "C:\\Windows\\System32\\lsass.exe"), "Computer": "dc01.corp.example"},
                                  explicit("2024-02-05T02:00:00Z", "fs01", "10.0.0.2", "C:\\Windows\\System32\\svchost.exe")],
                                 "Windows.EventLogs.EvtxHunter", client_id="C.1")
    used = leads.explicit_credentials(case)
    # Not localhost or the machine itself; a remote-admin tool's first, the routine ones after.
    assert [(u["server"], u["count"]) for u in used] == [("Desktop-001", 2), ("desktop-005", 1), ("fs01", 1)]
    assert used[0]["by"] == "svc" and used[0]["address"] == "10.0.24.1" and used[0]["programs"][0].endswith("PsExec.exe")
    assert used[0]["first"]["timestamp_utc"].startswith("2024-02-05T23:19:01") and used[0]["first"]["by_logon_id"] == "0x77"

    recent = "C:\\Users\\svc\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"
    case.ingest_artifact_results([
        {"SourceFile": {"OSPath": recent + "files.example.org on 198.51.100.7.lnk", "Btime": "2024-02-06T19:56:19Z"},
         "LinkTarget": {"LinkTarget": "871C5380-42A0-1069-A2EA-08002B30309D\\example.org"}},
        {"SourceFile": {"OSPath": recent + "q3.lnk", "Btime": "2024-02-06T20:00:00Z"},
         "LinkInfo": {"NetworkShareInfo": {"NetName": "\\\\FILESRV\\finance"}}},
        {"SourceFile": {"OSPath": recent + "notes.lnk", "Btime": "2024-02-06T20:05:00Z"},
         "LinkInfo": {"LocalBasePath": "C:\\Users\\svc\\Documents\\notes.txt"}},
    ], "Windows.Forensics.Lnk", client_id="C.1")
    remote = {r["host"]: r for r in leads.remote_locations(case)}
    assert set(remote) == {"198.51.100.7", "filesrv"}
    assert remote["198.51.100.7"]["scope"] == "external" and remote["198.51.100.7"]["via"] == [
        "Internet folder (FTP or WebDAV location)"] and remote["198.51.100.7"]["examples"][0].endswith("198.51.100.7.lnk")
    summary = json.loads(tools.case_summary.invoke({}))["leads"]
    assert summary["credentials_used_for_other_hosts"] and summary["remote_locations_opened"]


def test_programs_in_user_folders_carry_when_they_arrived(case):
    case.ingest_artifact_results([
        {"FullPath": "c:\\users\\svc\\desktop\\payload.exe", "SHA1": "ab" * 20, "Timestamp": "2024-02-07T21:00:10Z"},
    ], "Windows.Forensics.Amcache/InventoryApplicationFile", client_id="C.1")
    case.ingest_artifact_results([
        # Extracted from an archive that kept its times: only the change time says when it was written here.
        {"OSPath": "\\\\.\\C:\\Users\\svc\\Desktop\\payload.exe", "IsDir": False, "Size": 10,
         "BTime": "2016-03-24T00:00:00Z", "MTime": "2016-03-24T00:00:00Z", "CTime": "2024-02-06T20:13:40.4511Z"},
        {"OSPath": "C:\\Users\\svc\\Downloads\\tool.exe", "IsDir": False, "BTime": "2024-02-05T23:14:00.2207Z"},
        {"OSPath": "C:\\Users\\svc\\Desktop\\notes.txt", "IsDir": False, "BTime": "2024-02-05T23:00:00.1Z"},
    ] + [{"OSPath": f"C:\\Users\\Administrator\\Downloads\\Suite\\t{i}.exe", "IsDir": False,
          "BTime": f"2023-11-04T15:33:{i:02d}.5Z"} for i in range(40)], "Windows.Search.FileFinder", client_id="C.1")
    suite, tool, payload = leads.user_folder_programs(case)               # in order of arrival
    assert suite["programs"] == 40 and suite["folder"].endswith("\\Suite")          # one entry, not 40
    assert suite["created"]["timestamp_utc"] < suite["last_created"]["timestamp_utc"]
    assert tool["path"].endswith("tool.exe") and "inventoried" not in tool and "look" not in tool   # listed only
    assert payload["look"] == leads.COPIED_TIME                            # 2016 is not when it arrived
    assert payload["metadata_changed"]["timestamp_utc"].startswith("2024-02-06T20:13:40")
    assert payload["inventoried"]["timestamp_utc"].startswith("2024-02-07T21:00:10") and payload["sha1"]
    from copilot import checks
    assert checks.copied_time_files(case) == ["payload.exe"]               # its MFT record is read before investigating


def test_each_account_first_logon_and_first_rdp_from_a_source_are_shown(case):
    ip = "198.51.100.20"
    case.ingest_artifact_results([
        _logon(4624, "2024-02-05T22:55:18Z", "Administrator", ip, "kali", 3, "706976421"),
        _logon(4624, "2024-02-05T23:00:28Z", "Administrator", ip, "kali", 10, "707000001"),
        _logon(4624, "2024-02-05T23:05:22Z", "svc-new", ip, "kali", 10, "707379083"),
        _logon(4624, "2024-02-05T23:24:53Z", "svc-new", ip, "kali", 10, "709718015"),
    ], "Windows.EventLogs.EvtxHunter", client_id="C.1")
    [source] = leads.logon_sources(case, ip=ip)["sources"]
    assert source["first_success"]["timestamp_utc"].startswith("2024-02-05T22:55:18")
    firsts = source["first_success_by_account"]
    assert firsts["Administrator"] == {"first_rdp": {"timestamp_utc": firsts["Administrator"]["first_rdp"]["timestamp_utc"],
                                                     "evidence_id": firsts["Administrator"]["first_rdp"]["evidence_id"],
                                                     "logon_type": "10"}}
    assert firsts["Administrator"]["first_rdp"]["timestamp_utc"].startswith("2024-02-05T23:00:28")
    assert list(firsts["svc-new"]) == ["first"] and firsts["svc-new"]["first"]["timestamp_utc"].startswith("2024-02-05T23:05:22")
