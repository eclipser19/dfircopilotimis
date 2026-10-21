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
