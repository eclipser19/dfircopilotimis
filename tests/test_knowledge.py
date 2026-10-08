import pytest

from copilot import knowledge, tools


def test_all_knowledge_files_are_valid():
    arts = knowledge.artifacts()
    assert all({"pattern", "what", "location", "meaning"} <= set(a) for a in arts)
    assert all({"id", "channel", "meaning"} <= set(e) for e in knowledge.event_ids())
    assert all({"question", "check"} <= set(p) for p in knowledge.playbooks().values())


@pytest.mark.parametrize("name,expected", [
    ("Windows.Forensics.Usn", "USN"),
    ("Windows.NTFS.MFT", "Master File Table"),
    ("Windows.EventLogs.EvtxHunter/Source", "Search across"),
    ("windows.system.taskscheduler/Analysis", "Scheduled tasks"),
])
def test_artifact_lookup(name, expected):
    assert expected in knowledge.artifact_info(name)["what"]


def test_specific_patterns_win_over_general():
    assert "PowerShell" in knowledge.artifact_info("Windows.EventLogs.PowershellScriptblock")["what"]


def test_live_only():
    assert knowledge.is_live_only("Windows.System.Services")
    assert knowledge.is_live_only("Windows.Network.Netstat")
    assert not knowledge.is_live_only("Windows.NTFS.MFT")


def test_event_ids_disambiguated_by_channel():
    assert knowledge.event_info(4624)["meaning"] == "Successful logon"
    assert knowledge.event_info(22) == {}  # LocalSessionManager or Sysmon: ambiguous without channel
    assert knowledge.event_info(22, "Microsoft-Windows-Sysmon/Operational")["meaning"].startswith("Sysmon")
    assert knowledge.event_info(104, "System")["meaning"] == "Event log cleared"
    assert knowledge.logon_type(10) == "RemoteInteractive (RDP)"


def test_guide_tool():
    assert "4648" in tools.dfir_guide.invoke({"topic": "lateral movement"})
    assert "Successful logon" in tools.dfir_guide.invoke({"topic": "event id 4624"})
    assert "PathRegex" in tools.dfir_guide.invoke({"topic": "Windows.NTFS.MFT"})
    assert "LIVE SYSTEM ONLY" in tools.dfir_guide.invoke({"topic": "Windows.System.Services"})
    assert "Playbooks:" in tools.dfir_guide.invoke({"topic": "astrology"})


def test_questions_get_the_matching_playbook():
    from copilot import knowledge
    assert knowledge.playbooks_for("How did coreupdater.exe get onto this machine?") == ["initial_access"]
    assert knowledge.playbooks_for("Which process owned the connection to 203.78.103.109?") == ["memory", "indicator"]
    assert knowledge.playbooks_for("haven't you seen anything related to 194.61.24.102") == ["indicator"]
    assert knowledge.playbooks_for("investigate that ip, think of the places where you can find it") == ["indicator"]
    assert "analyze_memory strings" in knowledge.with_playbooks("anything related to 194.61.24.102?")
    assert knowledge.playbooks_for("Was data stolen?") == ["collection_exfiltration"]
    assert knowledge.playbooks_for("summarize the case") == []
    attached = knowledge.with_playbooks("How did coreupdater.exe get onto this machine?")
    assert attached.startswith("How did coreupdater.exe get onto this machine?\n\n[Copilot] Playbook")
    assert "EvidenceOfDownload" in attached and "Prefetch" in attached
    assert knowledge.with_playbooks("summarize the case") == "summarize the case"


def test_lessons_about_a_playbook_come_with_it(tmp_path, monkeypatch):
    from copilot import knowledge, lessons
    lessons.add("initial_access", "Check the Zone.Identifier stream of the payload's current path first.")
    assert "Zone.Identifier stream of the payload" in knowledge.with_playbooks("how did it get in?")


def test_collections_of_artifacts_that_cannot_work_on_images_are_marked(case):
    import json
    from copilot import tools
    case.upsert_collection("F.EDGE", client_id="C.1", artifact="Windows.Applications.Edge.History",
                           state="FINISHED", rows_ingested=0)
    case.upsert_collection("F.MFT", client_id="C.1", artifact="Windows.NTFS.MFT", state="FINISHED", rows_ingested=0)
    listed = {c["flow_id"]: c for c in json.loads(tools.list_collections.invoke({}))}
    assert "not evidence" in listed["F.EDGE"]["note"] and "note" not in listed["F.MFT"]
