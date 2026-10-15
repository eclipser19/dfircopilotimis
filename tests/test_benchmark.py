"""The benchmark: scoring answers against an answer key, and a full run with a scripted model."""
import json
import os

import pytest
import yaml
from langchain_core.messages import AIMessage

from copilot import benchmark, cases, collection, conversation
from copilot.case_config import case_config
from conftest import CLIENT, FakeVQL

SPEC = {
    "name": "mini",
    "case_file": "case.yaml",
    "clock_offset_minutes": 60,
    "time_tolerance_seconds": 60,
    "forbidden": [{"pattern": r"loot\.zip", "why": "desktop event"}],
    "questions": [
        {"id": "entry", "ask": "How did they get in?",
         "facts": [{"id": "brute", "what": "brute force from 194.61.24.102", "all": ["194.61.24.102"],
                    "any": [["brute", "4625"]], "time": "02:19:00-02:21:59"},
                   {"id": "admin", "what": "as Administrator", "any": [["administrator"]]}]},
        {"id": "malware", "ask": "What malware?",
         "facts": [{"id": "download", "what": "download", "any": [["coreupdater"]], "time": "02:24:06"},
                   {"id": "unsure", "what": "an unconfirmed detail", "any": [["system32"]], "scored": False}]},
        {"id": "memory", "memory": True, "ask": "What does memory show?",
         "facts": [{"id": "c2", "what": "C2", "all": ["203.78.103.109"]}]},
    ],
}


def _spec(tmp_path, spec=SPEC, case=None):
    folder = tmp_path / "spec"
    folder.mkdir(exist_ok=True)
    (folder / "benchmark.yaml").write_text(yaml.safe_dump(spec))
    (folder / "case.yaml").write_text(yaml.safe_dump(case or {
        "case": {"name": "Mini"}, "velociraptor": {"client_id": ""},
        "scope": {"clock_offset_minutes": 60}, "collect": ["Generic.Client.Info"],
        "agent": {"approvals": {"update_case": "confirm"}}}))
    return str(folder / "benchmark.yaml")


def test_times_are_scored_as_corrected_utc_and_recorded_ones_are_not_mistakes(tmp_path):
    spec = benchmark.load_spec(_spec(tmp_path))
    answer = ("Brute force from 194.61.24.102: 4625 events from 02:19:26 UTC (recorded 03:19:26) to "
              "02:21:40 UTC (recorded 03:21:40), then a logon as Administrator.")
    facts = {f["id"]: f for f in benchmark.score_answer(answer, spec["questions"][0], spec)["facts"]}
    assert facts["brute"]["found"] and facts["brute"]["time_ok"] and facts["brute"]["time_seen"] == "02:19:26"
    assert "uncorrected" not in facts["brute"] and facts["admin"]["found"]
    kinds = [(t[3], t[2]) for t in benchmark.answer_times(answer)]
    assert kinds == [("02:19:26", "utc"), ("03:19:26", "recorded"), ("02:21:40", "utc"), ("03:21:40", "recorded")]

    wrong = "coreupdater.exe was downloaded at 03:24:06 UTC."             # the host clock, called UTC
    fact = benchmark.score_answer(wrong, spec["questions"][1], spec)["facts"][0]
    assert fact["found"] and not fact["time_ok"] and fact["uncorrected"] == "03:24:06"
    far = "coreupdater.exe was downloaded. " + "x" * 600 + " Something else happened at 02:24:06 UTC."
    assert not benchmark.score_answer(far, spec["questions"][1], spec)["facts"][0]["time_ok"]   # too far away


def test_citations_and_forbidden_claims(case, tmp_path):
    spec = benchmark.load_spec(_spec(tmp_path))
    case.ingest_artifact_results([{"Message": "x"}], "S", "H", CLIENT)
    real = case.search_events("x")["records"][0]["evidence_id"]
    answer = f"Seen in `{real}` and `0123456789abcdef`; finding 12345678-abc; they also made loot.zip."
    score = benchmark.score_answer(answer, spec["questions"][0], spec, db=case)
    assert score["citations"]["evidence_cited"] == 2 and score["citations"]["evidence_invalid"] == ["0123456789abcdef"]
    assert score["citations"]["findings_invalid"] == ["12345678-abc"]
    assert score["forbidden"] == [{"pattern": r"loot\.zip", "why": "desktop event"}]
    t = benchmark.totals([{"id": "entry", "score": score}])
    assert t["invalid_ids"] == 2 and t["forbidden"] == 1 and t["facts_total"] == 2 and t["facts_found"] == 0


def test_a_spec_without_anything_to_look_for_is_refused(tmp_path):
    bad = dict(SPEC, questions=[{"id": "q", "ask": "?", "facts": [{"id": "f", "time": "02:00"}]}])
    with pytest.raises(benchmark.BenchmarkError, match="no all/any/regex"):
        benchmark.load_spec(_spec(tmp_path, bad))
    bad = dict(SPEC, questions=[{"id": "q", "ask": "?", "facts": [{"id": "f", "any": [["x"]], "time": "2 pm"}]}])
    with pytest.raises(benchmark.BenchmarkError, match="Not a time of day"):
        benchmark.load_spec(_spec(tmp_path, bad))


class ScriptedLLM:
    def __init__(self, *responses):
        self.responses = list(responses)

    def invoke(self, history):
        return self.responses.pop(0)


@pytest.fixture
def bench_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(collection, "get_vql", lambda: FakeVQL())
    monkeypatch.setattr(collection, "time", __import__("types").SimpleNamespace(monotonic=lambda: 0,
                                                                               sleep=lambda s: None))
    saved = (case_config.path, dict(case_config.data), cases.case_db.case_dir)
    yield tmp_path
    case_config.path, case_config.data = saved[0], saved[1]
    cases.case_db.open(saved[2])
    cases.consume_switch()


def test_a_full_run_scores_saves_and_leaves_a_readable_case(bench_dirs):
    spec_path = _spec(bench_dirs)
    llm = ScriptedLLM(
        AIMessage(content="", tool_calls=[{"name": "case_summary", "id": "1", "args": {}}]),
        AIMessage(content="RDP brute force (4625) from 194.61.24.102 at 02:20:00 UTC (recorded 03:20:00)."),
        AIMessage(content="coreupdater.exe, downloaded at 03:24:06 UTC."))
    results = benchmark.run(spec_path, client_id=CLIENT, model=(llm, llm, "scripted"),
                            out_dir=str(bench_dirs / "results"), log=lambda *a: None)
    run_id = results["run_id"]
    assert run_id.startswith("bench-mini-") and case_config.client_id == CLIENT
    approvals = case_config.data["agent"]["approvals"]
    assert approvals["update_case"] == "off" and approvals["memory"] == "auto"
    assert case_config.agent_collections == "auto"
    assert any("Generic.Client.Info -> FINISHED" in line for line in results["triage"])
    by_id = {q["id"]: q for q in results["questions"]}
    assert by_id["memory"]["skipped"] and by_id["entry"]["steps"] == 2
    assert [c["name"] for c in by_id["entry"]["tools"]] == ["case_summary"]
    t = results["totals"]
    assert (t["facts_found"], t["facts_total"], t["times_ok"], t["times_total"]) == (2, 3, 1, 2)
    assert t["uncorrected_times"] == 1 and t["unscored_total"] == 1 and t["score_percent"] == 60.0
    saved = json.loads((bench_dirs / "results" / f"{run_id}.json").read_text(encoding="utf-8"))
    assert saved["totals"] == t
    report = (bench_dirs / "results" / f"{run_id}.md").read_text(encoding="utf-8")
    assert "**Score 60.0%**" in report and "uncorrected time 03:24:06" in report
    ui, _ = conversation.load(run_id, "system")
    assert [m["role"] for m in ui] == ["user", "assistant", "user", "assistant"]

    # The answer key gets corrected: saved answers are scored again without running anything.
    fixed = json.loads(json.dumps(SPEC))
    fixed["questions"][0]["facts"][1]["scored"] = False
    with open(spec_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(fixed, f)
    again = benchmark.rescore(str(bench_dirs / "results" / f"{run_id}.json"))
    assert again["totals"]["facts_total"] == 2

    assert benchmark.clean(log=lambda *a: None) == [run_id]       # dry run: lists, removes nothing
    assert os.path.isdir(bench_dirs / "cases" / run_id)


def test_a_run_needs_an_evidence_client(bench_dirs):
    with pytest.raises(benchmark.BenchmarkError, match="--client"):
        benchmark.run(_spec(bench_dirs), model=(None, None, "x"), log=lambda *a: None)


def test_rescoring_an_old_run_skips_memory_questions_when_volatility_could_not_read_the_image(tmp_path):
    spec_path = _spec(tmp_path)
    results = {"name": "mini", "spec": spec_path, "run_id": "bench-mini-1", "case_id": "bench-mini-1",
               "triage": ["Generic.Client.Info -> FINISHED: rows 1",
                          "Memory.windows.info.Info -> ERROR: Volatility has no symbol table for this image's kernel",
                          "Memory.windows.pslist.PsList -> ERROR: Volatility has no symbol table for this image's kernel"],
               "questions": [{"id": "memory", "ask": "?", "answer": "Nothing could be read.", "score": {}},
                             {"id": "entry", "ask": "?", "answer": "4625 burst from 194.61.24.102 at 02:20 UTC"}]}
    path = tmp_path / "old.json"
    path.write_text(json.dumps(results))
    again = benchmark.rescore(str(path))
    assert again["questions"][0]["skipped"].endswith("(setup)") and again["totals"]["questions"] == 1
    report = (tmp_path / "bench-mini-1.md").read_text(encoding="utf-8")
    assert "⚠ **Setup:** Volatility cannot read the memory image" in report and "## Triage" in report


def test_within_ties_the_words_of_a_fact_together_and_cut_ids_are_invalid(tmp_path):
    spec = benchmark.load_spec(_spec(tmp_path))
    fact = {"id": "dl", "what": "download from the IP", "all": ["194.61.24.102"], "any": [["download"]], "within": 60}
    near = "coreupdater.exe was downloaded from http://194.61.24.102/ at 02:24:12 UTC."
    far = "It was downloaded to C:/Users/x/Downloads. " + "Unrelated text. " * 10 + "RDP from 194.61.24.102."
    assert benchmark.match_fact(near, fact)[0] and not benchmark.match_fact(far, fact)[0]
    assert benchmark.match_fact(far, dict(fact, within=None))[0]          # without within: anywhere
    cites = benchmark.check_citations("see `ba06dfce83ba6f8` and `0123456789abcdef0`", db=None)
    assert cites["evidence_invalid"] == ["ba06dfce83ba6f8", "0123456789abcdef0"]


@pytest.mark.parametrize("name", ["szechuan-dc", "corporatesecrets", "injector", "ou-server2022"])
def test_shipped_benchmarks_load_and_their_case_files_parse(name):
    root = os.path.join(os.path.dirname(__file__), "..", "cases", name)
    spec = benchmark.load_spec(os.path.join(root, "benchmark.yaml"))
    with open(os.path.join(root, spec["case_file"]), encoding="utf-8") as f:
        assert yaml.safe_load(f)["collect"]


def test_corporatesecrets_key_scores_a_good_answer_and_not_a_vague_one():
    spec = benchmark.load_spec(os.path.join(os.path.dirname(__file__), "..", "cases", "corporatesecrets",
                                            "benchmark.yaml"))
    tor = next(q for q in spec["questions"] if q["id"] == "privacy_tools")
    good = ("Tor Browser is installed in C:\\Program1. jim.tomato used Tor: a Start Tor Browser.lnk "
            "is on his desktop and RecentApps shows 2 launches.")
    vague = "No anonymisation software found. Users: jim.tomato, tim.apple. Programs in C:\\Program1 are unknown."
    found = {f["id"]: benchmark.score_fact(good, f, spec)["found"] for f in tor["facts"]}
    assert found == {"tor": True, "tor_path": True, "tor_user": True, "tor_runs": True}
    assert not any(benchmark.score_fact(vague, f, spec)["found"] for f in tor["facts"])


def _triage(artifact, rows, windowed):
    s = {"artifact": artifact, "state": "FINISHED", "rows_collected_by_velociraptor": rows}
    if windowed:
        s["time_window_applied"] = ["DateAfter", "DateBefore"]
    return s


def test_a_client_reading_another_image_stops_the_run():
    # What run 103116 looked like: the DC benchmark against a client still remapped to another image.
    wrong = [_triage("Generic.Client.Info", 22, False), _triage("Windows.EventLogs.RDPAuth", 0, True),
             _triage("Windows.Sys.StartupItems", 3, False), _triage("Windows.Timeline.Prefetch", 0, True),
             _triage("Windows.EventLogs.EvtxHunter", 0, True)]
    assert "another image" in benchmark.image_problem(wrong)
    right = wrong[:1] + [_triage("Windows.EventLogs.RDPAuth", 388, True)] + wrong[2:]
    assert benchmark.image_problem(right) == ""            # Prefetch off on a server is fine
    assert benchmark.image_problem([_triage("Generic.Client.Info", 22, False)]) == ""
    # Run 121906: the event-log collections passed the row limit and failed; only Prefetch (off on
    # servers) finished, with 0 rows. Not a wrong image: no conclusion.
    too_many = dict(_triage("Windows.EventLogs.EvtxHunter", 0, True), state="ERROR", row_limit=True)
    assert benchmark.image_problem([_triage("Generic.Client.Info", 22, False),
                                    _triage("Windows.Timeline.Prefetch", 0, True), too_many]) == ""


def test_a_run_without_an_answer_key_says_so():
    results = {"name": "x", "run_id": "bench-x-1", "case_id": "bench-x-1", "questions": [],
               "totals": benchmark.totals([{"id": "q", "answer": "a", "score": benchmark.score_answer("a", {"id": "q"}, {})}])}
    assert "No answer key yet" in benchmark.render_markdown(results)
