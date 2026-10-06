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
