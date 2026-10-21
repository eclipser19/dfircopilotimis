"""Files typed by their first bytes (copilot/file_types.py): the rules, "@file_types", the lead."""
import json
import re

import pytest

from copilot import collection, file_types, leads
from conftest import FakeVQL


def test_every_type_becomes_a_rule_and_extensions_decide_a_mismatch():
    rules = file_types.yara_rules()
    names = re.findall(r"^rule (\w+) \{", rules, re.M)
    assert len(names) == len(file_types.types()) == len(set(names)) and "FileType_sevenzip" in names
    assert 'what = "7-Zip archive"' in rules and '$pdf in (0..1024)' in rules
    mismatch = file_types.mismatch
    assert mismatch(r"C:\Users\m\Pictures\vegetable", "FileType_sevenzip") == {"content": "7-Zip archive",
                                                                                "extension": "(none)"}
    assert mismatch(r"C:\Users\m\Pictures\holiday.JPG", "FileType_pe")["extension"] == "jpg"
    assert mismatch(r"C:\Users\m\Documents\plan.docx", "FileType_zip") == {}          # Office files are ZIPs
    assert mismatch(r"C:\Users\m\Documents\locked.docx", "FileType_ole") == {}        # so are encrypted ones
    assert mismatch(r"C:\Users\m\Downloads\setup.exe.crdownload", "FileType_pe") == {}   # partial download
    assert mismatch(r"C:\Users\m\Downloads\backup.7z.001", "FileType_sevenzip") == {}
    assert mismatch(r"C:\Users\m\Desktop\.hidden", "FileType_zip")["extension"] == "(none)"
    assert mismatch("C:/x/y.zip", "SomeOtherRule") == {}                                 # not one of ours


def test_the_rules_compile_and_recognise_headers():
    yara = pytest.importorskip("yara")                    # not a dependency: checked where it is installed
    rules = yara.compile(source=file_types.yara_rules())
    assert [m.rule for m in rules.match(data=b"7z\xbc\xaf\x27\x1c" + bytes(32))] == ["FileType_sevenzip"]
    assert [m.rule for m in rules.match(data=b"PK\x03\x04" + bytes(32))] == ["FileType_zip"]
    assert rules.match(data=b"plain text " * 20) == []


def test_file_types_parameter_is_sent_as_rules_and_kept_by_name(case):
    vql = FakeVQL(artifact_params=["PathGlob", "YaraRule", "SizeMax"])
    params = {"PathGlob": "C:/Users/*/{Desktop,Pictures}/**", "YaraRule": "@file_types", "SizeMax": 50000000}
    collection.collect("Generic.Detection.Yara.Glob", params, vql=vql, sleep=lambda s: None)
    query, env = next(call for call in vql.calls if "collect_client" in call[0])
    sent = json.loads(env["DfirSpec"])["Generic.Detection.Yara.Glob"]
    assert sent["YaraRule"] == file_types.yara_rules() and sent["SizeMax"] == "50000000"
    stored = json.loads(case.get_collections()[0]["parameters"])
    assert stored["YaraRule"] == "@file_types"
    audit = case.conn.execute("SELECT query FROM audit_log WHERE tool_name = 'collect_artifact'").fetchone()[0]
    assert "@file_types" in audit and "FileType_" not in audit


def test_the_lead_lists_files_whose_content_is_not_their_name(case):
    rows = [{"OSPath": r"C:\Users\m\Pictures\vegetable", "Size": 4096, "Rule": "FileType_sevenzip",
             "Meta": {"what": "7-Zip archive"}, "Mtime": "2020-04-12T02:32:09Z"},
            {"OSPath": r"C:\Users\m\Pictures\cat.jpg", "Size": 2048, "Rule": "FileType_jpeg",
             "Meta": {"what": "JPEG image"}, "Mtime": "2020-04-12T02:00:00Z"},
            {"OSPath": r"C:\Users\m\Documents\report.docx", "Size": 9000, "Rule": "FileType_zip",
             "Meta": {"what": "ZIP container"}, "Mtime": "2020-04-11T01:00:00Z"},
            {"OSPath": r"C:\Users\m\Desktop\invoice.pdf", "Size": 70000, "Rule": "FileType_pe",
             "Meta": {"what": "Windows executable (PE)"}, "Mtime": "2020-04-10T01:00:00Z"},
            {"OSPath": r"C:\Users\m\Desktop\notes.txt", "Size": 10, "Rule": "Malware_X", "Mtime": "2020-04-10T01:00:00Z"}]
    case.ingest_artifact_results(rows, "Generic.Detection.Yara.Glob", "H", "C.1")
    found = leads.leads(case)["files_whose_content_is_not_their_name"]
    assert [(f["path"].rsplit("\\", 1)[1], f["extension"]) for f in found] == [("invoice.pdf", "pdf"),
                                                                                ("vegetable", "(none)")]
    assert found[1]["content"] == "7-Zip archive" and found[1]["evidence_id"]
    [description] = [r[0] for r in case.conn.execute("SELECT description FROM records WHERE description LIKE '%vegetable%'")]
    assert description == (r"C:\Users\m\Pictures\vegetable matched YARA rule FileType_sevenzip "
                                  "(7-Zip archive), 4096 bytes")
