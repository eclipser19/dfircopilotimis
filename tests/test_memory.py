"""Memory analysis with Volatility 3 (the Volatility process is faked; output as 2.28 renders it)."""
import json
import os

import pytest

from copilot import approvals, cases, memory, tools
from copilot.case_config import case_config
from conftest import CLIENT

PSLIST = [
    {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2020-09-19T01:22:43+00:00", "ExitTime": None,
     "Offset(V)": 1, "Threads": 120, "Handles": None, "SessionId": None, "Wow64": False, "File output": "Disabled",
     "__children": []},
    {"PID": 3644, "PPID": 600, "ImageFileName": "coreupdater.ex", "CreateTime": "2020-09-19T03:42:42+00:00",
     "ExitTime": "2020-09-19T03:56:37+00:00", "Offset(V)": 2, "Threads": 0, "Handles": None, "SessionId": 0,
     "Wow64": False, "File output": "Disabled", "__children": []},
]
NETSCAN = [{"Offset": 1, "Proto": "TCPv4", "LocalAddr": "10.42.85.115", "LocalPort": 49679,
            "ForeignAddr": "203.78.103.109", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 3644,
            "Owner": "spoolsv.exe", "Created": "2020-09-19T03:56:37+00:00", "__children": []}]
PSTREE = [{"PID": 600, "PPID": 4, "ImageFileName": "services.exe", "CreateTime": "2020-09-19T01:22:50+00:00",
           "__children": [{"PID": 3644, "PPID": 600, "ImageFileName": "coreupdater.ex",
                           "CreateTime": "2020-09-19T03:42:42+00:00", "__children": []}]}]
OUTPUT = {"windows.pslist.PsList": PSLIST, "windows.netscan.NetScan": NETSCAN, "windows.pstree.PsTree": PSTREE}


class FakeVolatility:
    """Stands in for the Volatility process: answers by plugin name, records every command."""

    def __init__(self, fail=None):
        self.commands = []
        self.fail = fail or {}

    def __call__(self, cmd):
        self.commands.append(cmd)
        plugin = next(c for c in cmd if c.startswith(("windows.", "linux.")))
        if plugin in self.fail:
            return 1, self.fail[plugin], "Volatility 3 Framework 2.28.2\nUnable to validate the plugin requirements"
        return 0, "\n" + json.dumps(OUTPUT.get(plugin, []), indent=2), "Volatility 3 Framework 2.28.2\n"


@pytest.fixture
def mem(case, tmp_path, monkeypatch):
    images = tmp_path / "memory"
    (images / "sub").mkdir(parents=True)
    (images / "desktop.mem").write_bytes(b"\0" * 2048)
    (images / "sub" / "dc01.vmem").write_bytes(b"\0" * 10)
    (images / "notes.txt").write_text("not an image")
    monkeypatch.setenv("DFIR_MEMORY_DIR", str(images))
    monkeypatch.setenv("DFIR_VOL_SYMBOLS", str(tmp_path / "symbols"))
    monkeypatch.setenv("DFIR_VOL_OFFLINE", "1")
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT},
                                              "memory": {"image": "desktop.mem"}})
    fake = FakeVolatility()
    monkeypatch.setattr(memory, "_run_process", fake)
    monkeypatch.setattr(memory, "available_plugins",
                        lambda: {n for p in memory.PLUGINS.values() for n in p.names})
    monkeypatch.setattr(memory, "version", lambda: "2.28.2")
    return fake


def test_plugin_rows_land_in_the_case_database(case, mem):
    summary = memory.run("windows.pslist")
    assert summary["state"] == "FINISHED" and summary["rows_read"] == 2 and summary["new_rows_ingested"] == 2
    events = case.query_timeline()["events"]
    assert {e["source"] for e in events} == {"Memory.windows.pslist.PsList"}
    assert any("process coreupdater.ex PID 3644 PPID 600" in e["description"] for e in events)
    assert {e["timestamp_utc"][:19] for e in events} >= {"2020-09-19T03:42:42", "2020-09-19T03:56:37"}
    flow = case.get_collection(summary["flow_id"])
    assert flow["state"] == "FINISHED" and flow["client_id"] == "memory:desktop.mem" and flow["ingested"] == 1
    assert memory.run("windows.pslist")["new_rows_ingested"] == 0          # re-running adds no duplicates


def test_the_command_volatility_gets(case, mem, tmp_path):
    memory.run("windows.pslist", {"pid": ["3644", 600], "contains": "core,updater.ex"})
    cmd = mem.commands[-1]
    tail = cmd[cmd.index("-q"):]
    assert tail[:3] == ["-q", "-r", "json"]
    assert tail[tail.index("-s") + 1] == str(tmp_path / "symbols") and "--offline" in tail
    assert tail[tail.index("-f") + 1] == str(tmp_path / "memory" / "desktop.mem")
    assert tail[tail.index("windows.pslist.PsList") + 1:] == ["--pid", "3644", "600"]
    assert tail[tail.index("--filters") + 1] == r"+(?i)core\x2cupdater\.ex!"     # no comma: Volatility splits on it
    assert cmd[:2] == [__import__("sys").executable, "-c"] and "volatility3.cli" in cmd[2]


def test_tree_output_is_flattened_and_netscan_owner_is_a_process(case, mem):
    memory.run("windows.pstree")
    memory.run("windows.netscan")
    rows = case.search_events("coreupdater")["records"]
    assert any(r["source"] == "Memory.windows.pstree.PsTree" for r in rows)
    net = case.search_events("203.78.103.109")["records"][0]
    assert net["event_type"] == "network" and net["process"] == "spoolsv.exe" and not net.get("user")
    assert "-> 203.78.103.109:443 ESTABLISHED owner spoolsv.exe PID 3644" in net["description"]
    assert case.pivot_entity("203.78.103.109")["total"] >= 1


def test_images_must_be_in_the_memory_folder(case, mem, monkeypatch):
    assert [i["name"] for i in memory.available_images()] == ["desktop.mem", "sub/dc01.vmem"]
    for bad in ("../memory/../case.db", "nope.mem"):
        with pytest.raises(memory.MemoryAnalysisError):
            memory.image_path(bad)
    monkeypatch.delenv("DFIR_MEMORY_DIR")
    with pytest.raises(memory.MemoryAnalysisError, match="memory.images_dir"):
        memory.image_path("desktop.mem")
    monkeypatch.setattr(case_config, "data", {})
    with pytest.raises(memory.MemoryAnalysisError, match="No memory image is set"):
        memory.run("windows.pslist")


def test_only_allowed_plugins_and_options(case, mem):
    with pytest.raises(memory.MemoryAnalysisError, match="not an allowed memory plugin"):
        memory.run("windows.memmap")
    with pytest.raises(memory.MemoryAnalysisError, match="does not take key"):
        memory.run("windows.pslist", {"key": "x"})
    with pytest.raises(memory.MemoryAnalysisError, match="recurse needs a key"):
        memory.run("windows.registry.printkey", {"recurse": True})
    with pytest.raises(memory.MemoryAnalysisError, match="list of process IDs"):
        memory.run("windows.pslist", {"pid": ["abc"]})
    assert memory.resolve("windows.malware.malfind.Malfind")[0] == "windows.malfind"
    assert not any("dump" in c for cmd in mem.commands for c in cmd)


def test_agent_needs_a_filter_for_heavy_plugins_and_approval(case, mem, monkeypatch):
    out = tools.analyze_memory.invoke({"plugin": "windows.handles"})
    assert "Narrow it with contains or pid" in out and not mem.commands
    out = tools.analyze_memory.invoke({"plugin": "windows.netscan"})
    assert "needs the investigator's approval" in out and not mem.commands       # no approval channel
    asked = []
    monkeypatch.setattr(approvals, "ASK", lambda r: asked.append(r) or True)
    out = json.loads(tools.analyze_memory.invoke({"plugin": "windows.handles", "pid": [3644]}))
    assert out["state"] == "FINISHED"
    assert asked[0]["kind"] == "memory" and "windows.handles (pid=[3644]) on desktop.mem" in asked[0]["summary"]


def test_queued_memory_request_runs_when_approved(case, mem, monkeypatch):
    queue = []
    monkeypatch.setattr(approvals, "ASK", lambda r: queue.append(r) or "queued")
    assert "Waiting for the investigator's approval" in tools.analyze_memory.invoke({"plugin": "windows.netscan"})
    assert not mem.commands
    result = approvals.resolve(queue[0], True, actor="alice")
    assert result["state"] == "FINISHED" and case.search_events("203.78.103.109")["total"] == 1


def test_case_setting_can_let_the_agent_run_memory_freely(case, mem):
    case_config.data["agent"] = {"approvals": {"memory": "auto"}}
    assert json.loads(tools.analyze_memory.invoke({"plugin": "windows.netscan"}))["state"] == "FINISHED"


def test_missing_symbols_offline_are_explained(case, mem, tmp_path):
    mem.fail["windows.info.Info"] = ("\nUnsatisfied requirement plugins.Info.kernel.symbol_table_name: \n\n"
                                     "A symbol table requirement was not fulfilled.")
    summary = memory.run("windows.info")
    assert summary["state"] == "ERROR"
    assert "not allowed to download" in summary["error"] and str(tmp_path / "symbols") in summary["error"]
    assert "windows.zip" in summary["error"]
    assert case.get_collection(summary["flow_id"])["state"] == "ERROR"


def test_unreadable_file_is_explained(case, mem):
    mem.fail["windows.pslist.PsList"] = "Unsatisfied requirement plugins.PsList.kernel.layer_name: "
    assert "could not read this file as a memory image" in memory.run("windows.pslist")["error"]


def test_row_limit(case, mem):
    case_config.data["collection"] = {"max_rows": 1}
    summary = memory.run("windows.pslist")
    assert summary["rows_read"] == 1 and "only the first 1 were stored" in summary["note"]


def test_triage_runs_the_default_plugins_and_reports_setup_problems_once(case, mem, monkeypatch):
    seen = []
    summaries = memory.triage(progress=seen.append)
    assert seen == memory.TRIAGE["windows"] and all(s["state"] == "FINISHED" for s in summaries)
    case_config.data["memory"] = {"image": "desktop.mem", "collect": ["windows.netscan"]}
    assert memory.triage_plan() == ["windows.netscan"]
    case_config.data["memory"] = {"image": "gone.mem"}
    result = memory.triage()
    assert len(result) == 1 and result[0]["state"] == "NOT_STARTED" and "was not found" in result[0]["error"]


def test_case_settings_pick_an_image_from_the_folder(mem, tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    cases.create("m", "Memory case", memory_image="sub/dc01.vmem")
    with pytest.raises(cases.CaseError, match="No memory image 'secret.yaml'"):
        cases.update("m", memory_image="secret.yaml")
    cases.update("m", memory_image="desktop.mem", memory_os="windows")
    cases.switch("m")
    assert case_config.memory_image == "desktop.mem"
    assert "Memory image: desktop.mem" in case_config.build_system_context()


def test_check_command(case, mem, capsys):
    assert memory.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "Volatility 3 version: 2.28.2" in out and "desktop.mem (2 KB)" in out and "Offline: yes" in out
    assert memory.main([]) == 1


def test_missing_volatility_is_explained(case, monkeypatch, tmp_path):
    monkeypatch.setattr(memory, "command", lambda: [os.path.join(str(tmp_path), "no-such-python")])
    memory._available.update(names=None, version=None)
    with pytest.raises(memory.MemoryAnalysisError, match="pip install volatility3"):
        memory.available_plugins()
    memory._available.update(names=None, version=None)


# ---- Against the real Volatility, when it is installed (no memory image needed) ----

@pytest.fixture
def real_volatility():
    pytest.importorskip("volatility3")
    memory._available.update(names=None, version=None)
    yield
    memory._available.update(names=None, version=None)


def test_every_allowed_plugin_exists_in_the_installed_volatility(real_volatility):
    import importlib.util
    available = memory.available_plugins()
    missing = [short for short, spec in memory.PLUGINS.items()
               if spec.names and not spec.requires and not any(n in available for n in spec.names)]
    assert not missing, f"not in Volatility {memory.version()}: {missing}"
    # Plugins that need an extra package (YARA) are listed only when it is installed: the module must exist.
    for spec in memory.PLUGINS.values():
        if spec.requires:
            assert any(importlib.util.find_spec("volatility3.plugins." + n.rsplit(".", 1)[0])
                       for n in spec.names), spec.names


def test_real_volatility_on_a_file_that_is_not_an_image(case, real_volatility, tmp_path, monkeypatch):
    images = tmp_path / "memory"
    images.mkdir()
    (images / "random.raw").write_bytes(os.urandom(2_000_000))
    monkeypatch.setenv("DFIR_MEMORY_DIR", str(images))
    monkeypatch.setenv("DFIR_VOL_SYMBOLS", str(tmp_path / "symbols"))
    monkeypatch.setenv("DFIR_VOL_OFFLINE", "1")
    monkeypatch.setattr(case_config, "data", {"memory": {"image": "random.raw"}})
    summary = memory.run("windows.info")
    assert summary["state"] == "ERROR" and "symbol table" in summary["error"]


def test_report_names_the_memory_image_and_capture_time(case, mem):
    from copilot.report import build_report
    OUTPUT["windows.info.Info"] = [{"Variable": "SystemTime", "Value": "2020-09-19 05:10:39+00:00", "__children": []},
                                   {"Variable": "NtMajorVersion", "Value": "10", "__children": []}]
    try:
        memory.run("windows.info")
        memory.run("windows.netscan")
    finally:
        del OUTPUT["windows.info.Info"]
    report = build_report(case, case_config, "ES", "- R")
    assert "- **Disk evidence:** Velociraptor client " + CLIENT in report
    assert "- **Memory image:** desktop.mem, captured 2020-09-19 05:10:39+00:00 (host clock)" in report
    assert "Memory.windows.netscan.NetScan" in report
    assert case.search_events("SystemTime")["records"][0]["description"] == \
        "memory image SystemTime: 2020-09-19 05:10:39+00:00"


def test_symbols_dir_pointing_at_a_table_says_which_folder_to_use(case, mem, tmp_path, monkeypatch, capsys):
    symbols = tmp_path / "volatility3" / "symbols"
    table = symbols / "windows" / "ntkrnlmp.pdb" / "81BC5C377C525081645F9958F209C527-1.json.xz"
    table.parent.mkdir(parents=True)
    table.write_bytes(b"")
    for wrong in (table, table.parent, table.parent.parent):
        monkeypatch.setenv("DFIR_VOL_SYMBOLS", str(wrong))
        with pytest.raises(memory.MemoryAnalysisError) as e:
            memory.run("windows.info")
        assert str(e.value).endswith(str(symbols) + ("." if wrong == table else ""))
    assert not case.get_collections() and not mem.commands           # nothing started, nothing left RUNNING
    assert memory.main(["check"]) == 1 and "points to a file" not in capsys.readouterr().out   # last one: a folder
    monkeypatch.setenv("DFIR_VOL_SYMBOLS", str(table))
    assert memory.main(["check", "desktop.mem"]) == 1 and "points to a file" in capsys.readouterr().out
    result = memory.triage()
    assert len(result) == 1 and "points to a file" in result[0]["error"]
    for fine in (symbols, tmp_path / "windows" / "temp" / "symbols"):     # C:\Windows\... is not a symbols sub-folder
        monkeypatch.setenv("DFIR_VOL_SYMBOLS", str(fine))
        assert memory.symbols_problem() == ""


def test_check_accepts_the_full_path_of_an_image_in_the_folder(case, mem, tmp_path, capsys):
    mem.fail = {}
    OUTPUT["windows.info.Info"] = [{"Variable": "NtMajorVersion", "Value": "10"},
                                   {"Variable": "SystemTime", "Value": "2020-09-19 05:10:39+00:00"}]
    try:
        assert memory.main(["check", str(tmp_path / "memory" / "desktop.mem")]) == 0
    finally:
        del OUTPUT["windows.info.Info"]
    assert "OK: Windows 10" in capsys.readouterr().out


def test_identical_rows_are_stored_once(case, mem):
    service = {"Offset": 1, "Name": "coreupdater", "Display": "coreupdater", "State": "SERVICE_RUNNING",
               "Start": "SERVICE_AUTO_START", "Binary": "C:\\Windows\\System32\\coreupdater.exe", "__children": []}
    OUTPUT["windows.svcscan.SvcScan"] = [dict(service) for _ in range(60)] + [dict(service, Offset=2)]
    try:
        summary = memory.run("windows.svcscan")
    finally:
        del OUTPUT["windows.svcscan.SvcScan"]
    assert summary["rows_read"] == 2 and summary["duplicates_dropped"] == 59
    from copilot.agent import status_line
    assert status_line(summary) == ("Memory.windows.svcscan.SvcScan -> FINISHED: rows 2, new 2, "
                                    "59 repeated rows dropped (0 s)")


# ---- Searching memory: the image file itself (strings) and YARA per process ----

def _hex(text, wide=False):
    return (text.encode("utf-16-le") if wide else text.encode()).hex(" ")


VADYARA = [  # as Volatility 2.28 renders windows.vadyarascan with -r json (Value = the matched bytes)
    {"Offset": 4096, "PID": 3644, "CreateTime": "2020-09-19T03:42:42+00:00", "PPID": 600,
     "ImageFileName": "spoolsv.exe", "SessionId": 0, "Threads": 9, "Rule": "r1", "Component": "$a",
     "Value": _hex("203.78.103.109:443"), "__children": []},
    {"Offset": 8192, "PID": 3644, "CreateTime": "2020-09-19T03:42:42+00:00", "PPID": 600,
     "ImageFileName": "spoolsv.exe", "SessionId": 0, "Threads": 9, "Rule": "r1", "Component": "$a",
     "Value": _hex("203.78.103.109:443"), "__children": []},
    {"Offset": 64, "PID": 860, "CreateTime": "2020-09-19T03:36:40+00:00", "PPID": 700,
     "ImageFileName": "MicrosoftEdge.", "SessionId": 2, "Threads": 30, "Rule": "r1", "Component": "$a",
     "Value": _hex("203.78.103.109/x", wide=True), "__children": []},
]


def test_yara_text_search_names_the_processes_that_hold_it(case, mem):
    OUTPUT["windows.vadyarascan.VadYaraScan"] = VADYARA
    try:
        summary = memory.run("windows.vadyarascan", {"text": "203.78.103.109"})
    finally:
        del OUTPUT["windows.vadyarascan.VadYaraScan"]
    cmd = mem.commands[-1]
    assert cmd[cmd.index("--yara-string") + 1] == r"/203\.78\.103\.109[ -~]{0,100}/"
    assert "--wide" in cmd and "--insensitive" in cmd
    assert summary["rows_read"] == 2                        # one row per process and matched text
    events = case.query_timeline()["events"]
    descriptions = sorted(e["description"] for e in events)
    assert descriptions == ['MicrosoftEdge. PID 860 memory holds "203.78.103.109/x" (UTF-16), 1x',
                            'spoolsv.exe PID 3644 memory holds "203.78.103.109:443" (ASCII), 2x']
    assert {e["event_type"] for e in events} == {"memory_search"}
    assert case.search_events("203.78.103.109")["total"] == 2


def test_yara_rule_files_come_from_the_server_folder(case, mem, tmp_path, monkeypatch):
    rules = tmp_path / "yara"
    rules.mkdir()
    (rules / "meterpreter.yar").write_text("rule m { strings: $a = \"metsrv\" condition: $a }")
    (rules / "notes.txt").write_text("x")
    with pytest.raises(memory.MemoryAnalysisError, match="memory.yara_dir"):
        memory.run("windows.vadyarascan", {"rules": "meterpreter.yar"})
    monkeypatch.setenv("DFIR_YARA_DIR", str(rules))
    assert memory.rule_files() == ["meterpreter.yar"]
    for bad in ("../yara/../case.db", "notes.txt", "nope.yar"):
        with pytest.raises(memory.MemoryAnalysisError, match="Available: meterpreter.yar"):
            memory.run("windows.vadyarascan", {"rules": bad})
    OUTPUT["windows.vadyarascan.VadYaraScan"] = [dict(VADYARA[0], Rule="default.m", Value=_hex("metsrv.dll"))]
    try:
        memory.run("windows.vadyarascan", {"rules": "meterpreter.yar", "pid": [3644]})
    finally:
        del OUTPUT["windows.vadyarascan.VadYaraScan"]
    cmd = mem.commands[-1]
    assert cmd[cmd.index("--yara-file") + 1] == str(rules / "meterpreter.yar") and "--pid" in cmd
    assert any("rule default.m" in r["description"] for r in case.search_events("metsrv")["records"])
    listed = {p["plugin"]: p for p in memory.plugin_list()}
    assert listed["windows.vadyarascan"]["rule_files"] == ["meterpreter.yar"]


def test_searches_need_one_sensible_text_or_rules(case, mem):
    for options, message in (({}, "exactly one of rules or text"),
                             ({"text": "abc", "rules": "x.yar"}, "exactly one of"),
                             ({"text": "ab"}, "4 to 200 printable ASCII"),
                             ({"text": "caf\u00e9.example"}, "printable ASCII")):
        with pytest.raises(memory.MemoryAnalysisError, match=message):
            memory.run("windows.vadyarascan", options)
    with pytest.raises(memory.MemoryAnalysisError, match="does not take text"):
        memory.run("windows.pslist", {"text": "1.2.3.4"})
    assert not mem.commands


def test_yara_missing_says_what_to_install(case, mem, monkeypatch):
    monkeypatch.setattr(memory, "available_plugins", lambda: {"windows.pslist.PsList"})
    with pytest.raises(memory.MemoryAnalysisError, match="pip install yara-x"):
        memory.run("windows.vadyarascan", {"text": "203.78.103.109"})
    assert memory.main(["check"]) == 0


def test_strings_searches_the_image_file_without_volatility(case, mem, tmp_path, monkeypatch):
    request = b"GET http://194.61.24.102/coreupdater.exe HTTP/1.1\r\n"
    url = "http://194.61.24.102/coreupdater.exe".encode("utf-16-le")
    monkeypatch.setattr(memory, "_CHUNK", 32)              # hits across chunk borders
    (tmp_path / "memory" / "desktop.mem").write_bytes(b"\0" * 40 + request + b"\x01" * 70 + url + b"\0" * 9 + request)
    summary = memory.run("strings", {"text": "194.61.24.102"})
    assert summary["state"] == "FINISHED" and summary["rows_read"] == 2 and not mem.commands
    descriptions = sorted(r["description"] for r in case.search_events("194.61.24.102")["records"])
    assert descriptions == [
        'memory image holds "GET http://194.61.24.102/coreupdater.exe HTTP/1.1" (ASCII), 2x first at 0x33',
        'memory image holds "http://194.61.24.102/coreupdater.exe" (UTF-16), 1x first at 0xaf']
    missing = memory.run("strings", {"text": "10.99.99.99"})
    assert missing["rows_read"] == 0 and "nowhere in the image" in missing["note"]
    rows, truncated = memory.search_image(str(tmp_path / "memory" / "desktop.mem"), "coreupdater", max_hits=1)
    assert truncated and len(rows) == 1


def test_searches_are_not_part_of_the_triage(case, mem):
    assert "windows.pslist" in memory.triage_plugins("windows")
    assert "windows.vadyarascan" not in memory.triage_plugins("windows") and "strings" not in memory.triage_plugins("windows")
    with pytest.raises(cases.CaseError, match="can't be part of the triage"):
        cases._check_memory_triage(["windows.pslist", "windows.vadyarascan"])


def test_agent_searches_memory_with_approval(case, mem, approve_all):
    out = json.loads(tools.analyze_memory.invoke({"plugin": "strings", "text": "203.78.103.109"}))
    assert out["state"] == "FINISHED" and out["rows_read"] == 0
    assert approve_all[0]["summary"] == "strings (text=203.78.103.109) on desktop.mem"
