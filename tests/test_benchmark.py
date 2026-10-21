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

    timeline = "- **5 February 02:24:06:** coreupdater.exe was downloaded."  # a time as a list item's label
    assert benchmark.score_answer(timeline, spec["questions"][1], spec)["facts"][0]["time_ok"]
    assert [t[3] for t in benchmark.answer_times("MAC 00:12:34:56:78:9a, at 7:05")] == ["7:05"]


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
                            out_dir=str(bench_dirs / "results"), log=lambda *a: None, investigate_first=False)
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


def test_the_investigation_runs_first_and_every_question_starts_from_its_dossier(bench_dirs):
    prompts = []

    class Recording(ScriptedLLM):
        def invoke(self, history):
            prompts.append(history[0].content)
            return super().invoke(history)

    llm = Recording(
        AIMessage(content="", tool_calls=[{"name": "case_summary", "id": "1", "args": {}}]),
        AIMessage(content="## Intrusion timeline\n- 02:20:00 UTC brute force from 194.61.24.102"),
        AIMessage(content="From the dossier: brute force from 194.61.24.102 at 02:20:00 UTC."),
        AIMessage(content="coreupdater.exe"))
    results = benchmark.run(_spec(bench_dirs), client_id=CLIENT, model=(llm, llm, "scripted"),
                            out_dir=str(bench_dirs / "results"), log=lambda *a: None)
    inv = results["investigation"]
    assert inv["dossier"].startswith("## Intrusion timeline") and inv["steps"] == 2 and inv["tool_calls"] == 1
    assert "## CASE DOSSIER" not in prompts[0]                              # nothing to start from yet
    assert all("- 02:20:00 UTC brute force from 194.61.24.102" in p for p in prompts[2:]) and len(prompts) == 4
    t = results["totals"]
    assert t["investigated"] and t["steps"] == 4 and t["tool_calls"] == 1 and t["facts_found"] == 2
    report = (bench_dirs / "results" / f"{results['run_id']}.md").read_text(encoding="utf-8")
    assert f"**Investigation first:** dossier of {len(inv['dossier'])} characters · 2 steps" in report
    assert "## Case dossier (investigation)" in report
    ui, _ = conversation.load(results["run_id"], "system")
    assert ui[0]["content"].startswith("**Case dossier**")


def test_reusing_an_earlier_run_takes_its_triage_only_and_collects_what_it_lacks(bench_dirs, monkeypatch):
    from datetime import datetime, timezone
    from copilot.database import case_db
    vql = FakeVQL(unique_flows=True)                                        # a flow ID per collection
    monkeypatch.setattr(collection, "get_vql", lambda: vql)
    quiet = {"out_dir": str(bench_dirs / "results"), "log": lambda *a: None, "investigate_first": False}
    first = benchmark.run(_spec(bench_dirs), client_id=CLIENT, model=(ScriptedLLM(AIMessage(content="a"),
                                                                                  AIMessage(content="b")), None, "s"),
                          **quiet)
    # What that run's agent collected after the triage must not reach the next run.
    case_db.upsert_collection("F.AGENT", client_id=CLIENT, artifact="Windows.Search.FileFinder", state="FINISHED",
                              requested_at=datetime.now(timezone.utc).isoformat(), rows_ingested=1)
    case_db.ingest_artifact_results([{"Message": "collected later by the agent"}], "Windows.Search.FileFinder",
                                    "H", CLIENT)
    # The triage has grown since, even by the artifact that agent collected with its own filters.
    spec = _spec(bench_dirs, case={"case": {"name": "Mini"}, "velociraptor": {"client_id": ""},
                                   "collect": ["Generic.Client.Info", "Windows.Sys.StartupItems",
                                               "Windows.Search.FileFinder"]})
    second = benchmark.run(spec, from_case=first["run_id"],
                           model=(ScriptedLLM(AIMessage(content="c"), AIMessage(content="d")), None, "s"), **quiet)
    assert second["from_case"] == first["run_id"] and "(its triage only)" in second["triage"][0]
    assert case_config.client_id == CLIENT                                  # the evidence comes with it
    assert case_db.search_events("collected later")["total"] == 0 and case_db.get_stats()["total_records"] >= 1
    assert {c["artifact"] for c in case_db.get_collections()} == {"Generic.Client.Info", "Windows.Sys.StartupItems",
                                                                   "Windows.Search.FileFinder"}
    assert "F.AGENT" not in {c["flow_id"] for c in case_db.get_collections()}
    for collected_now in ("Windows.Sys.StartupItems -> ", "Windows.Search.FileFinder -> "):
        assert any(line.startswith(collected_now) for line in second["triage"])
    assert second["code"].get("commit")                                     # which code produced the run


def test_a_triage_entry_whose_parameters_changed_is_collected_again_and_kept_as_triage(bench_dirs, monkeypatch):
    from copilot.database import case_db
    vql = FakeVQL(unique_flows=True)
    monkeypatch.setattr(collection, "get_vql", lambda: vql)
    quiet = {"out_dir": str(bench_dirs / "results"), "log": lambda *a: None, "investigate_first": False}
    model = lambda: (ScriptedLLM(AIMessage(content="a"), AIMessage(content="b")), None, "s")

    def spec(ids):
        return _spec(bench_dirs, case={"case": {"name": "Mini"}, "velociraptor": {"client_id": ""}, "collect": [
            {"artifact": "Windows.EventLogs.EvtxHunter", "parameters": {"IdRegex": ids}}]})
    first = benchmark.run(_spec(bench_dirs, case={"case": {"name": "Mini"}, "velociraptor": {"client_id": CLIENT},
                                                  "collect": [{"artifact": "Windows.EventLogs.EvtxHunter",
                                                               "parameters": {"IdRegex": "^(4624)$"}}]}),
                          model=model(), **quiet)
    second = benchmark.run(spec("^(4624|4732)$"), from_case=first["run_id"], model=model(), **quiet)
    assert any(line.startswith("Windows.EventLogs.EvtxHunter -> ") for line in second["triage"])   # an ID added
    third = benchmark.run(spec("^(4624|4732)$"), from_case=second["run_id"], model=model(), **quiet)
    assert len(third["triage"]) == 1                                       # both copied, nothing collected
    assert [json.loads(c["parameters"])["IdRegex"] for c in case_db.get_collections()] == ["^(4624)$",
                                                                                           "^(4624|4732)$"]


def test_a_broken_model_stops_the_run_before_anything_is_collected(bench_dirs, monkeypatch):
    class Broken:
        def invoke(self, messages):
            raise ConnectionError("no route to the endpoint")
    monkeypatch.setattr("copilot.llm.make_llm", lambda key=None: Broken())
    monkeypatch.setattr("copilot.llm.needs_user_key", lambda: False)
    with pytest.raises(benchmark.BenchmarkError, match="did not answer .*nothing was collected yet"):
        benchmark.run(_spec(bench_dirs), client_id=CLIENT, log=lambda *a: None)
    assert not os.path.isdir(bench_dirs / "cases")                          # no run case was even created


def test_a_triage_only_run_does_not_investigate(bench_dirs):
    results = benchmark.run(_spec(bench_dirs), client_id=CLIENT, model=(ScriptedLLM(), None, "scripted"),
                            only=["none"], out_dir=str(bench_dirs / "results"), log=lambda *a: None)
    assert "investigation" not in results and results["questions"] == []


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


def test_triage_still_running_is_waited_for_and_reported_if_it_never_ends(tmp_path, monkeypatch):
    monkeypatch.setattr(benchmark, "TRIAGE_POLL_SECONDS", 0)
    states = iter(["IN_PROGRESS", "FINISHED"])
    check = lambda flow_id: {"flow_id": flow_id, "artifact": "Windows.EventLogs.EvtxHunter", "state": next(states)}
    summaries = [{"flow_id": "F.1", "artifact": "Generic.Client.Info", "state": "FINISHED"},
                 {"flow_id": "F.2", "artifact": "Windows.EventLogs.EvtxHunter", "state": "IN_PROGRESS"}]
    done = benchmark.finish_triage(summaries, 1, log=lambda *a: None, sleep=lambda s: None, check=check)
    assert [s["state"] for s in done] == ["FINISHED", "FINISHED"]
    # Nothing waits when everything finished; a run saved without waiting gets a setup warning.
    assert benchmark.finish_triage(done, 1, log=lambda *a: None, check=None) == done
    results = {"name": "mini", "spec": _spec(tmp_path), "run_id": "bench-mini-2", "case_id": "bench-mini-2",
               "triage": ["Windows.EventLogs.EvtxHunter -> IN_PROGRESS (time window: DateAfter, DateBefore)"],
               "questions": [{"id": "entry", "ask": "?", "answer": "nothing"}]}
    path = tmp_path / "old.json"
    path.write_text(json.dumps(results))
    assert "Triage still running" in benchmark.rescore(str(path))["setup"][0]


def test_within_ties_the_words_of_a_fact_together_and_cut_ids_are_invalid(tmp_path):
    spec = benchmark.load_spec(_spec(tmp_path))
    fact = {"id": "dl", "what": "download from the IP", "all": ["194.61.24.102"], "any": [["download"]], "within": 60}
    near = "coreupdater.exe was downloaded from http://194.61.24.102/ at 02:24:12 UTC."
    far = "It was downloaded to C:/Users/x/Downloads. " + "Unrelated text. " * 10 + "RDP from 194.61.24.102."
    assert benchmark.match_fact(near, fact)[0] and not benchmark.match_fact(far, fact)[0]
    assert benchmark.match_fact(far, dict(fact, within=None))[0]          # without within: anywhere
    cites = benchmark.check_citations("see `ba06dfce83ba6f8` and `0123456789abcdef0`", db=None)
    assert cites["evidence_invalid"] == ["ba06dfce83ba6f8", "0123456789abcdef0"]


def test_a_claim_named_only_to_deny_or_doubt_it_is_not_found():
    injected = {"id": "inj", "what": "backdoor injected into spoolsv.exe", "any": [["spoolsv"], ["inject"]],
                "within": 300}
    hedged = ("spoolsv.exe held the C2 string. This does not prove that spoolsv.exe was injected, and whether "
              "it reflects injected code remains undetermined.")
    assert benchmark.match_fact(hedged, injected) == (False, [], True)
    assert benchmark.match_fact(hedged + " Malfind shows spoolsv.exe was injected.", injected)[0]
    # The names a claim is tied to count anywhere; the claim needs a clause that does not deny it.
    back = {"id": "back", "what": "came back", "all": ["194.61.24.102"], "any": [["reconnect", "came back"]]}
    text = ("The session was not yet over: the same source IP reconnected at 02:56:04.\n\n"
            "No later return from 194.61.24.102 was found.")
    assert benchmark.match_fact(text, back)[0]
    assert not benchmark.match_fact("I found no RDP reconnect from 194.61.24.102.", back)[0]
    # A list under a denying lead-in inherits it; a fact worded as a denial still matches its own words.
    group = {"id": "grp", "what": "added to Domain Admins", "any": [["domain admins", "4728"]]}
    assert not benchmark.match_fact("I found no evidence of:\n- Password reset (4724)\n- Group changes (4728)", group)[0]
    assert benchmark.match_fact("Changes found:\n- admin added to Domain Admins (4728)", group)[0]
    no_exploit = {"id": "nx", "what": "no exploit", "any": [["no software vulnerability"]]}
    assert benchmark.match_fact("Valid credentials were used; no software vulnerability was exploited.", no_exploit)[0]
    assert benchmark.match_fact("The 02:52:46 event was not the end of activity\u2014the attacker came back later.",
                                {"id": "x", "what": "x", "any": [["came back"]]})[0]
    group = {"id": "g", "what": "x", "any": [["4728"]]}         # a bare item of an inline list: its sentence counts
    assert benchmark.match_fact("Searches for group events\u20144732, 4728, and 4756\u2014returned no records.", group)[2]
    assert benchmark.match_fact("Group changes: 4732, 4728 and 4756 at 23:02.", group)[0]
    guest = {"id": "u", "what": "x", "all": ["guest"]}            # a heading item described by its line is not a list
    assert benchmark.match_fact("- **Guest** \u2014 built-in account, disabled, password not required.", guest)[0]


@pytest.mark.parametrize("name", ["szechuan-dc", "corporatesecrets", "injector", "ou-server2022"])
def test_shipped_benchmarks_load_and_their_case_files_parse(name):
    root = os.path.join(os.path.dirname(__file__), "..", "cases", name)
    spec = benchmark.load_spec(os.path.join(root, "benchmark.yaml"))
    with open(os.path.join(root, spec["case_file"]), encoding="utf-8") as f:
        assert yaml.safe_load(f)["collect"]


def test_a_run_saved_on_windows_finds_its_benchmark_anywhere(monkeypatch):
    monkeypatch.chdir(os.path.join(os.path.dirname(__file__), ".."))
    assert benchmark.load_spec("cases\\szechuan-dc\\benchmark.yaml")["name"]


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


def test_evidence_dump_shows_the_raw_records_an_answer_cites(bench_dirs):
    llm = ScriptedLLM(AIMessage(content="first"), AIMessage(content="second"))
    results = benchmark.run(_spec(bench_dirs), client_id=CLIENT, model=(llm, llm, "scripted"),
                            out_dir=str(bench_dirs / "results"), log=lambda *a: None, investigate_first=False)
    from copilot.database import case_db
    real = case_db.conn.execute("SELECT evidence_id FROM records LIMIT 1").fetchone()[0]
    path = bench_dirs / "results" / f"{results['run_id']}.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    saved["questions"][0]["answer"] = f"Host seen in `{real}`; also `0123456789abcdef`."
    path.write_text(json.dumps(saved), encoding="utf-8")
    dump = open(benchmark.evidence_dump(str(path)), encoding="utf-8").read()
    assert f"### `{real}` Generic.Client.Info" in dump and "WS01" in dump
    assert "`0123456789abcdef`: NOT IN THE CASE" in dump and "(no evidence IDs cited)" in dump


def test_clean_removes_run_folders_with_their_data(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.delenv("DFIR_DATA_DIR", raising=False)
    monkeypatch.delenv("DFIR_CASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    for run_id in ("bench-x-1", "bench-x-2"):
        os.makedirs(tmp_path / "cases" / run_id)
        (tmp_path / "cases" / run_id / "case.yaml").write_text("case:\n  name: x\n")
    os.makedirs(tmp_path / "cases" / "bench-x-1" / "data")                 # data in the case's folder
    os.makedirs(tmp_path / "case_data" / "bench-x-2")                      # data from before the move
    (tmp_path / "case_data" / "bench-x-2" / "case.db").write_text("db")
    os.makedirs(tmp_path / "cases" / "keep")
    (tmp_path / "cases" / "keep" / "case.yaml").write_text("case:\n  name: k\n")
    assert benchmark.clean(yes=True, log=lambda *a: None) == ["bench-x-1", "bench-x-2"]
    assert sorted(os.listdir(tmp_path / "cases")) == ["keep"]
    assert not (tmp_path / "case_data" / "bench-x-2").exists()
