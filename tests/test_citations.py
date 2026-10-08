import re

from copilot import citations
from copilot.case_config import case_config
from conftest import CLIENT


def _seed(case, monkeypatch, offset=60):
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT},
                                              "scope": {"clock_offset_minutes": offset}})
    case.ingest_artifact_results([{"Proto": "TCPv4", "LocalAddr": "10.42.85.115", "LocalPort": 49679,
                                   "ForeignAddr": "203.78.103.109", "ForeignPort": 443, "State": "ESTABLISHED",
                                   "PID": 3316, "Owner": "powershell.exe", "Created": "2020-09-19T05:08:44+00:00"}],
                                 "Memory.windows.netscan.NetScan", "x", "memory:x")
    eid = case.search_events("203.78.103.109")["records"][0]["evidence_id"]
    fid = case.record_finding("C2 connection from injected PowerShell", "d", [eid], "high")
    return eid, fid


def test_cited_ids_are_resolved_with_corrected_times(case, monkeypatch):
    eid, fid = _seed(case, monkeypatch)
    sha256 = "a" * 64                                            # hashes are not evidence IDs
    text = f"C2 at 04:08 UTC (`{eid}`), finding {fid}; also `{eid}` again, `0123456789abcdef` (unknown), {sha256}"
    found = citations.cited(text, case, case_config)
    assert found["evidence"] == [{"Evidence": eid, "Time (UTC)": "2020-09-19 04:08:44", "Recorded": "2020-09-19 05:08:44",
                                  "Source": "Memory.windows.netscan.NetScan",
                                  "What it shows": "TCPv4 10.42.85.115:49679 -> 203.78.103.109:443 ESTABLISHED "
                                                   "owner powershell.exe PID 3316"}]
    assert found["findings"] == [{"Finding": fid, "Title": "C2 connection from injected PowerShell",
                                  "Confidence": "high", "Status": "active"}]
    assert citations.summary(found) == "1 evidence record and 1 finding"
    text_out = citations.as_text(found)
    assert eid in text_out and "04:08:44 (rec 2020-09-19 05:08:44)" in text_out and fid in text_out


def test_no_recorded_column_without_clock_skew(case, monkeypatch):
    eid, _ = _seed(case, monkeypatch, offset=0)
    assert "Recorded" not in citations.cited(eid, case, case_config)["evidence"][0]
    assert citations.cited("nothing cited here", case, case_config) == {"evidence": [], "findings": []}


def test_evidence_text_cannot_become_markdown():
    evil = "{$b=$env:windir} ![p](http://evil.example/x.png) [click](https://evil.example) *b* <img src=x> www.evil.example"
    out = citations.md_literal(evil)
    chars = iter(out)
    for c in chars:                                                   # every punctuation character is escaped
        if c == "\\":
            next(chars)
        else:
            assert c.isalnum() or c.isspace() or not c.isascii(), (c, out)
    assert "http:/" not in re.sub(r"\\(.)", r"\1", out)               # URLs are broken up: no autolinks
    assert "www." not in re.sub(r"\\(.)", r"\1", out)
    assert re.sub(r"\\(.)", r"\1", out).replace("​", "") == evil  # and it shows exactly as it was
    assert citations.md_literal("line1\nline2") == "line1 line2"


def test_answers_keep_dollars_and_lose_images():
    out = citations.answer_markdown("ran $b=$env:windir ![x](http://evil.example/p.png) `$code` [MITRE](https://attack.mitre.org)")
    assert out == "ran \\$b=\\$env:windir [image removed: x] `$code` [MITRE](https://attack.mitre.org)"
    assert citations.answer_markdown("```\n$x = 1 ![a](b)\n```") == "```\n$x = 1 ![a](b)\n```"   # code stays as is
