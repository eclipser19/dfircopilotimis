"""
Benchmark: run the agent on a case with a fixed set of questions and score the answers against
an answer key (benchmark.yaml next to the case file), in code: free and repeatable.

    python -m copilot.benchmark run cases/szechuan-dc/benchmark.yaml --client C.<id>
    python -m copilot.benchmark run <spec> --from-case <case id>   # reuse that case's collected data
    python -m copilot.benchmark run <spec> --questions entry,malware
    python -m copilot.benchmark score benchmark_results/<run>.json # re-score saved answers
    python -m copilot.benchmark clean [--yes]                      # remove the bench-* cases

Every run works in a fresh case `bench-<name>-<time>` (its own database: runs never see each
other's findings or chats), with agent collections and memory runs approved automatically and
case changes and lessons switched off. Triage runs first without the LLM (skipped with
--from-case). Each question is asked in a fresh conversation, the way an investigator would
type it, with the matching playbooks attached. Results: benchmark_results/<run>.json and .md;
the questions and answers are also saved as the run case's chat, so it can be opened in the app.

Scoring, per fact of the answer key (see the header of cases/szechuan-dc/benchmark.yaml):
found (the expected words), time (a true-UTC time in range near those words), uncorrected time
(the recorded host time given as UTC), plus evidence/finding IDs that do not exist and
forbidden claims (e.g. another host's events).
"""
import argparse
import getpass
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone

import yaml

RESULTS_DIR = "benchmark_results"
TRIAGE_WAIT_MINUTES = 60     # how long a run waits for triage collections still running
TRIAGE_POLL_SECONDS = 30
RUN_PREFIX = "bench-"
CONTEXT_CHARS = 400          # how far from a fact's words its time may be
_TIME_RE = re.compile(r"(?<![\d:])([01]?\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?(?![\d:])")
_RECORDED_LABELS = ("recorded", "host time", "host clock", "local time")


class BenchmarkError(Exception):
    pass


# ---------------------------------------------------------------- spec
def load_spec(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        spec = yaml.safe_load(f) or {}
    spec["_path"] = path
    spec["_dir"] = os.path.dirname(os.path.abspath(path))
    if not spec.get("name") or not spec.get("questions"):
        raise BenchmarkError(f"{path}: a benchmark needs a name and questions.")
    for question in spec["questions"]:
        if not question.get("id") or not question.get("ask"):
            raise BenchmarkError(f"{path}: every question needs an id and ask.")
        for fact in question.get("facts") or []:
            if not (fact.get("all") or fact.get("any") or fact.get("regex")):
                raise BenchmarkError(f"{path}: fact '{fact.get('id')}' has no all/any/regex to look for.")
            if fact.get("time"):
                _time_range(fact["time"])            # fails early on a malformed time
    return spec


def _seconds(hms: str) -> int:
    try:
        parts = [int(p) for p in str(hms).strip().split(":")]
    except ValueError:
        parts = []
    if len(parts) == 2:
        parts.append(0)
    if len(parts) != 3 or not (0 <= parts[0] < 24 and 0 <= parts[1] < 60 and 0 <= parts[2] < 60):
        raise BenchmarkError(f"Not a time of day: {hms!r} (expected HH:MM or HH:MM:SS)")
    return parts[0] * 3600 + parts[1] * 60 + parts[2]


def _time_range(value: str) -> tuple:
    start, _, end = str(value).partition("-")
    return _seconds(start), _seconds(end or start)


def _hms(seconds: int) -> str:
    seconds %= 86400
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


# ---------------------------------------------------------------- scoring
def answer_times(text: str) -> list:
    """[(position, seconds of the day, 'utc' | 'recorded', as written)] for every time in the text."""
    found = []
    for m in _TIME_RE.finditer(text or ""):
        before = text[max(0, m.start() - 40):m.start()].lower()
        label = max((before.rfind(word), word) for word in _RECORDED_LABELS)
        # "02:24:06 UTC (recorded 03:24:06)": a time is recorded when a label comes just before it,
        # not closed by ")" and not followed by "utc" in between.
        recorded = label[0] >= 0 and ")" not in before[label[0]:] and "utc" not in before[label[0]:]
        seconds = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3) or 0)
        found.append((m.start(), seconds, "recorded" if recorded else "utc", m.group(0)))
    return found


def _positions(text: str, needle: str) -> list:
    return [m.start() for m in re.finditer(re.escape(needle.lower()), text.lower())]


def match_fact(text: str, fact: dict) -> tuple:
    """
    (found, positions of the words that matched). With `within: N`, every requirement must occur
    within N characters of the first one, so "downloaded ... from 1.2.3.4" counts but an IP named
    for something else three paragraphs away does not.
    """
    required = [_positions(text, needle) for needle in fact.get("all") or []]
    required += [[p for needle in group for p in _positions(text, needle)] for group in fact.get("any") or []]
    required += [[m.start() for m in re.finditer(pattern, text or "", re.I)] for pattern in fact.get("regex") or []]
    if not required or not all(required):
        return False, []
    window = fact.get("within")
    if not window:
        return True, sorted({p for where in required for p in where})
    for anchor in required[0]:
        near = [[p for p in where if abs(p - anchor) <= window] for where in required[1:]]
        if all(near):
            return True, sorted({anchor, *(p for where in near for p in where)})
    return False, []


def _within(seconds: int, start: int, end: int, tolerance: int) -> bool:
    return start - tolerance <= seconds <= end + tolerance


def score_fact(text: str, fact: dict, spec: dict) -> dict:
    found, hits = match_fact(text, fact)
    result = {"id": fact["id"], "what": fact.get("what", ""), "found": found,
              "scored": fact.get("scored", True) is not False}
    if fact.get("note"):
        result["note"] = fact["note"]
    if not fact.get("time"):
        return result
    start, end = _time_range(fact["time"])
    tolerance = int(fact.get("tolerance_seconds", spec.get("time_tolerance_seconds", 120)))
    offset = int(spec.get("clock_offset_minutes", 0)) * 60
    result.update(time_expected=fact["time"], time_ok=False)
    if not found:
        return result
    times = answer_times(text)
    near = [t for t in times if any(abs(t[0] - h) <= CONTEXT_CHARS for h in hits)]
    good = sorted((t for t in near if t[2] == "utc" and _within(t[1], start, end, tolerance)),
                  key=lambda t: max(start - t[1], t[1] - end, 0))     # closest to the expected time first
    if good:
        result.update(time_ok=True, time_seen=good[0][3])
        return result
    if offset:
        wrong = [t for t in near if t[2] == "utc" and _within(t[1], start + offset, end + offset, tolerance)]
        if wrong:
            result["uncorrected"] = wrong[0][3]
    seen = [t[3] for t in near if t[2] == "utc"]
    if seen:
        result["time_seen"] = ", ".join(dict.fromkeys(seen[:4]))
    return result


def _existing_ids(ids: list, table: str, column: str, db) -> set:
    if not ids or db is None:
        return set(ids)
    marks = ",".join("?" * len(ids))
    try:
        rows = db.conn.execute(f"SELECT {column} FROM {table} WHERE {column} IN ({marks})", ids).fetchall()
    except Exception:
        return set(ids)
    return {r[0] for r in rows}


def malformed_ids(text: str) -> list:
    """Cited like an evidence ID (in backticks) but cut short or too long: a copying mistake, never valid."""
    return list(dict.fromkeys(re.findall(r"`([0-9a-f]{12,15}|[0-9a-f]{17,20})`", text or "")))


def check_citations(text: str, db=None) -> dict:
    """Evidence and finding IDs the answer cites, and those that do not exist in the case."""
    from copilot.citations import EVIDENCE_RE, FINDING_RE
    evidence = list(dict.fromkeys(EVIDENCE_RE.findall(text or "")))
    malformed = malformed_ids(text)
    findings = list(dict.fromkeys(FINDING_RE.findall(text or "")))
    real_evidence = _existing_ids(evidence, "records", "evidence_id", db)
    real_findings = set()
    for fid in findings:          # finding IDs are matched by prefix in the database
        try:
            if db is None or db.find_finding(fid):
                real_findings.add(fid)
        except Exception:
            real_findings.add(fid)
    return {"evidence_cited": len(evidence) + len(malformed),
            "evidence_invalid": [e for e in evidence if e not in real_evidence] + malformed,
            "findings_cited": len(findings), "findings_invalid": [f for f in findings if f not in real_findings]}


def score_answer(text: str, question: dict, spec: dict, db=None, citations: dict = None) -> dict:
    forbidden = [{"pattern": f["pattern"], "why": f.get("why", "")} for f in spec.get("forbidden") or []
                 if re.search(f["pattern"], text or "", re.I)]
    return {"facts": [score_fact(text or "", fact, spec) for fact in question.get("facts") or []],
            "citations": citations if citations is not None else check_citations(text, db),
            "forbidden": forbidden}


def totals(questions: list, investigation: dict = None) -> dict:
    """Scores and costs of a run; the costs include the investigation turn, if one ran."""
    t = {"facts_found": 0, "facts_total": 0, "times_ok": 0, "times_total": 0, "uncorrected_times": 0,
         "invalid_ids": 0, "forbidden": 0, "unscored_found": 0, "unscored_total": 0, "errors": 0,
         "tokens_in": 0, "tokens_out": 0, "steps": 0, "tool_calls": 0, "seconds": 0, "questions": 0,
         "investigated": bool(investigation and investigation.get("dossier"))}
    for key in ("tokens_in", "tokens_out", "steps", "tool_calls", "seconds"):
        t[key] += (investigation or {}).get(key) or 0
    for q in questions:
        if q.get("skipped"):
            continue
        t["questions"] += 1
        t["errors"] += bool(q.get("error"))
        for key in ("tokens_in", "tokens_out", "steps", "seconds"):
            t[key] += q.get(key) or 0
        t["tool_calls"] += len(q.get("tools") or [])
        score = q.get("score") or {}
        for fact in score.get("facts", []):
            if not fact["scored"]:
                t["unscored_total"] += 1
                t["unscored_found"] += fact["found"]
                continue
            t["facts_total"] += 1
            t["facts_found"] += fact["found"]
            if "time_expected" in fact:
                t["times_total"] += 1
                t["times_ok"] += bool(fact.get("time_ok"))
            t["uncorrected_times"] += bool(fact.get("uncorrected"))
        cites = score.get("citations") or {}
        t["invalid_ids"] += len(cites.get("evidence_invalid", [])) + len(cites.get("findings_invalid", []))
        t["forbidden"] += len(score.get("forbidden", []))
    points = t["facts_total"] + t["times_total"]
    t["score_percent"] = round(100 * (t["facts_found"] + t["times_ok"]) / points, 1) if points else 0.0
    return t


# ---------------------------------------------------------------- report
def _mark(ok) -> str:
    return "✓" if ok else "✗"


def render_markdown(results: dict) -> str:
    t = results["totals"]
    lines = [
        f"# Benchmark {results['name']} — {results['run_id']}",
        "",
        f"Model `{results.get('model', '?')}` · case `{results['case_id']}` · {results.get('started', '')[:19]} UTC",
        "",
        (f"**Score {t['score_percent']}%** — facts {t['facts_found']}/{t['facts_total']}, "
         f"times {t['times_ok']}/{t['times_total']} · " if t["facts_total"] else
         "**No answer key yet** — answers saved; score them once the key has facts "
         "(`python -m copilot.benchmark score <this run>.json`) · ") +
        f"uncorrected times {t['uncorrected_times']} · "
        f"invalid IDs {t['invalid_ids']} · forbidden claims {t['forbidden']} · errors {t['errors']}",
        "",
        f"{t['questions']} questions · {t['steps']} model steps · {t['tool_calls']} tool calls · "
        f"{t['tokens_in']:,} tokens in / {t['tokens_out']:,} out · {round(t['seconds'] / 60, 1)} min"
        + (" (investigation included)" if results.get("investigation") else ""),
        "",
    ]
    inv = results.get("investigation")
    if inv:
        lines += [f"**Investigation first:** " + (f"dossier of {len(inv['dossier']):,} characters" if inv.get("dossier")
                                                    else f"no dossier ({inv.get('error') or 'no answer'})") +
                  f" · {inv.get('steps', 0)} steps · {inv.get('tokens_in', 0):,} tokens in · "
                  f"{round((inv.get('seconds') or 0) / 60, 1)} min", ""]
    else:
        lines += ["Questions answered without an investigation first (no case dossier).", ""]
    for problem in results.get("setup") or []:
        lines += [f"⚠ **Setup:** {problem}", ""]
    lines += [
        "| Question | Facts | Times | Invalid IDs | Steps | Tokens in | Min |",
        "|---|---|---|---|---|---|---|",
    ]
    for q in results["questions"]:
        if q.get("skipped"):
            lines.append(f"| {q['id']} | skipped: {q['skipped']} | | | | | |")
            continue
        facts = [f for f in q["score"]["facts"] if f["scored"]]
        timed = [f for f in facts if "time_expected" in f]
        cites = q["score"]["citations"]
        bad = len(cites.get("evidence_invalid", [])) + len(cites.get("findings_invalid", []))
        lines.append(f"| {q['id']} | {sum(f['found'] for f in facts)}/{len(facts)} | "
                     f"{sum(bool(f.get('time_ok')) for f in timed)}/{len(timed)} | {bad} | {q.get('steps', 0)} | "
                     f"{q.get('tokens_in', 0):,} | {round((q.get('seconds') or 0) / 60, 1)} |")
    for q in results["questions"]:
        if q.get("skipped"):
            continue
        lines += ["", f"## {q['id']}: {q['ask']}", ""]
        if q.get("error"):
            lines.append(f"**Error:** {q['error']}")
        for f in q["score"]["facts"]:
            line = f"- {_mark(f['found'])} {f['what']}"
            if "time_expected" in f:
                line += f" · time {_mark(f.get('time_ok'))} (expected {f['time_expected']} UTC"
                line += f", answer: {f['time_seen']})" if f.get("time_seen") else ")"
            if f.get("uncorrected"):
                line += f" · ⚠ uncorrected time {f['uncorrected']}"
            if not f["scored"]:
                line += f" · *not scored{': ' + f['note'] if f.get('note') else ''}*"
            lines.append(line)
        cites = q["score"]["citations"]
        lines.append(f"- Cited {cites.get('evidence_cited', 0)} evidence and {cites.get('findings_cited', 0)} "
                     f"finding IDs" + (f"; not in the case: {', '.join(cites['evidence_invalid'] + cites['findings_invalid'])}"
                                       if cites.get("evidence_invalid") or cites.get("findings_invalid") else ""))
        for f in q["score"]["forbidden"]:
            lines.append(f"- ⚠ forbidden claim `{f['pattern']}`: {f['why']}")
        tools = [c["name"] for c in q.get("tools") or []]
        if tools:
            lines.append(f"- Tools: {', '.join(tools)}")
        lines += ["", "<details><summary>Answer</summary>", "", (q.get("answer") or "(none)"), "", "</details>"]
    if inv and inv.get("dossier"):
        lines += ["", "## Case dossier (investigation)", "", "<details><summary>Dossier</summary>", "",
                  inv["dossier"], "", "</details>"]
    if results.get("triage"):
        fence = "~~~~"            # triage lines may contain backticks
        lines += ["", "## Triage", "", fence] + list(results["triage"]) + [fence]
    return "\n".join(lines) + "\n"


def save(results: dict, out_dir: str = RESULTS_DIR) -> tuple:
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, results["run_id"])
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1, ensure_ascii=False, default=str)
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write(render_markdown(results))
    return base + ".json", base + ".md"


# ---------------------------------------------------------------- running
def image_problem(summaries: list) -> str:
    """
    A setup check on the disk triage: collections filtered to the case's time window all came back
    empty while unfiltered ones returned rows. That is what a client reading another image looks like
    (its events are from other dates), so the run stops before spending tokens on questions.
    """
    disk = [s for s in summaries if not str(s.get("artifact", "")).startswith("Memory.")]
    if any(s.get("time_window_applied") and s.get("state") != "FINISHED" for s in disk):
        return ""          # a windowed collection failed (e.g. too many rows): no conclusion possible
    finished = [s for s in disk if s.get("state") == "FINISHED"]
    windowed = [s for s in finished if s.get("time_window_applied")]
    others = [s for s in finished if not s.get("time_window_applied")]
    if windowed and not any(s.get("rows_collected_by_velociraptor") for s in windowed) \
            and any(s.get("rows_collected_by_velociraptor") for s in others):
        names = ", ".join(s["artifact"] for s in windowed)
        return (f"Every triage collection limited to the case's time window returned 0 rows ({names}) while the "
                f"others returned rows: the client is probably reading another image, or the case window is wrong.")
    return ""


def make_run_case(spec: dict, run_id: str, client_id: str = None, memory_image: str = None, log=print) -> str:
    """Writes the run's case file from the spec's case template, with benchmark settings."""
    from copilot import cases, memory
    with open(os.path.join(spec["_dir"], spec.get("case_file", "case.yaml")), encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("case", {})["name"] = f"[benchmark] {data['case'].get('name') or spec['name']}"
    velo = data.setdefault("velociraptor", {})
    velo["client_id"] = client_id or velo.get("client_id") or ""
    if not velo["client_id"]:
        raise BenchmarkError("No evidence client: pass --client C.<id> (or --from-case) or set it in the case file.")
    mem = data.setdefault("memory", {})
    if memory_image is not None:
        mem["image"] = memory_image
    if mem.get("image") and mem["image"] not in {i["name"] for i in memory.available_images()}:
        log(f"[!] Memory image '{mem['image']}' is not in the server's memory folder: memory questions are skipped.")
        mem["image"] = ""
    data.setdefault("collection", {})["agent_collections"] = "auto"
    agent = data.setdefault("agent", {})
    agent["approvals"] = {"retract_finding": "auto", "memory": "auto", "update_case": "off",
                          "switch_case": "off", "create_case": "off", "lesson": "off"}
    data.pop("access", None)
    path = os.path.join(cases.cases_dir(), run_id, "case.yaml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Benchmark run of {spec['_path']} ({datetime.now(timezone.utc).isoformat()[:19]} UTC).\n")
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    return path


def make_model():
    from copilot import llm as llm_config
    from copilot.tools import tools
    key = getpass.getpass("API key for the LLM endpoint: ") if llm_config.needs_user_key() else None
    llm = llm_config.make_llm(key)
    return llm.bind_tools(tools), llm.bind_tools(tools, tool_choice="none"), llm_config.model_name()


def _emitter(steps_log: list, log=print):
    """run_turn's progress events, logged and kept in the results."""
    def emit(kind, payload):
        if kind in ("tool", "collection", "notice"):
            steps_log.append(f"{kind}: {payload}")
            log(f"    {'⚙' if kind == 'tool' else ' '} {payload}")
    return emit


def investigate(llm_with_tools, finalizer, extra: str = "", log=print) -> dict:
    """The investigation turn before the questions (copilot/dossier.py): its dossier and cost."""
    from copilot import dossier
    from copilot.agent import TokenUsage
    usage, steps_log = TokenUsage(), []
    started = time.monotonic()
    try:
        entry = dossier.investigate(llm_with_tools, finalizer, usage, _emitter(steps_log, log), extra)
        result = {"dossier": entry["text"], "steps": entry["steps"], "error": ""}
    except Exception as e:                    # the questions still run, without a dossier
        result = {"dossier": "", "steps": 0, "error": f"{type(e).__name__}: {e}"}
    return {**result, "log": steps_log, "tokens_in": usage.turn_input, "tokens_out": usage.turn_output,
            "tool_calls": sum(line.startswith("tool:") for line in steps_log),
            "seconds": round(time.monotonic() - started, 1)}


def ask(text: str, llm_with_tools, finalizer, log=print) -> dict:
    """One question in a fresh conversation, as typed by an investigator."""
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
    from copilot.agent import TokenUsage, run_turn
    from copilot.case_config import case_config
    from copilot.knowledge import with_playbooks
    from copilot.prompts import build_system_prompt
    history = [SystemMessage(content=build_system_prompt(case_config)), HumanMessage(content=with_playbooks(text))]
    usage, steps_log = TokenUsage(), []
    started, error, answer = time.monotonic(), "", ""
    try:
        answer = run_turn(llm_with_tools, history, case_config.max_steps, usage, case_config.max_tokens_per_turn,
                          finalizer, _emitter(steps_log, log))
    except Exception as e:                    # an LLM or tool failure ends this question, not the run
        error = f"{type(e).__name__}: {e}"
    calls = [{"name": c["name"], "args": c.get("args")} for m in history if isinstance(m, AIMessage)
             for c in (m.tool_calls or [])]
    return {"answer": answer, "error": error, "tools": calls, "log": steps_log,
            "steps": sum(isinstance(m, AIMessage) for m in history),
            "tokens_in": usage.turn_input, "tokens_out": usage.turn_output, "tokens_estimated": usage.estimated,
            "seconds": round(time.monotonic() - started, 1)}


def finish_triage(summaries: list, wait_minutes: float = TRIAGE_WAIT_MINUTES, log=print,
                  sleep=time.sleep, check=None) -> list:
    """
    Waits for triage collections that were still running when their own wait ran out, so every run
    of a benchmark starts from the same data (a run whose event-log triage is still running answers
    without the logons). Returns the summaries with the final states.
    """
    from copilot import collection
    check = check or collection.check
    summaries = list(summaries)
    pending = [i for i, s in enumerate(summaries)
               if s.get("flow_id") and s.get("state") not in collection.TERMINAL_STATES]
    deadline = time.monotonic() + wait_minutes * 60
    if pending:
        log(f"[*] Waiting up to {wait_minutes:g} min for triage still running: "
            f"{', '.join(summaries[i].get('artifact') or summaries[i]['flow_id'] for i in pending)}")
    while pending and time.monotonic() < deadline:
        sleep(TRIAGE_POLL_SECONDS)
        for i in list(pending):
            try:
                summaries[i] = check(summaries[i]["flow_id"])
            except collection.CollectionError as e:
                summaries[i] = {**summaries[i], "state": "ERROR", "error": str(e)}
            if summaries[i].get("state") in collection.TERMINAL_STATES:
                pending.remove(i)
                log(f"    {summaries[i].get('artifact')}: {summaries[i].get('state')}")
    return summaries


def run(spec_path: str, client_id: str = None, memory_image: str = None, from_case: str = None,
        skip_triage: bool = False, only: list = None, model=None, out_dir: str = RESULTS_DIR, log=print,
        image_check: bool = True, triage_wait: float = TRIAGE_WAIT_MINUTES, investigate_first: bool = True) -> dict:
    """
    Runs a benchmark end to end and saves its results. model: (llm_with_tools, finalizer, name) for tests.
    investigate_first: the investigation turn writes the case dossier before the questions (as the app does
    after triage); off, each question starts from the data alone (the runs before the dossier existed).
    """
    from copilot import cases, conversation, memory
    from copilot.agent import auto_collect, status_line
    from copilot.case_config import case_config
    from copilot.database import case_db
    spec = load_spec(spec_path)
    started = datetime.now(timezone.utc)
    run_id = f"{RUN_PREFIX}{spec['name']}-{started.strftime('%Y%m%d-%H%M%S')}"
    if from_case:
        client_id = client_id or (cases._read(from_case).get("velociraptor", {}) or {}).get("client_id")
    make_run_case(spec, run_id, client_id, memory_image, log)
    triage = []
    if from_case:
        counts = cases.copy_data(from_case, run_id)
        triage.append(f"Data copied from case {from_case}: {counts}")
    cases.switch(run_id)
    cases.consume_switch()
    log(f"[*] Benchmark {spec['name']}: case {run_id} (client {case_config.client_id}, "
        f"memory {case_config.memory_image or 'none'})")
    setup = []
    if not from_case and not skip_triage:
        disk = finish_triage(auto_collect(case_config), triage_wait, log)
        triage += [status_line(s) for s in disk]
        from copilot.collection import TERMINAL_STATES
        unfinished = [f"{s.get('artifact')} ({s.get('state')})" for s in disk
                      if s.get("flow_id") and s.get("state") not in TERMINAL_STATES]
        if unfinished:     # the questions start without that data: not comparable with other runs
            setup.append(f"Triage still running after {triage_wait:g} min: {', '.join(unfinished)}; "
                         f"the answers lack its data")
        problem = image_problem(disk) if image_check else ""
        if problem:
            raise BenchmarkError(f"{problem} Stopped before the questions (case {run_id}); check the client, "
                                 f"or pass --no-image-check to run anyway.")
        if case_config.memory_image:
            log("[*] Memory triage ...")
            triage += [status_line(s) for s in memory.triage(progress=lambda p: log(f"    {p}"))]
    memory_broken = memory.unreadable_reason(case_config.memory_image) if case_config.memory_image else ""
    if memory_broken:      # a setup problem (e.g. no symbol table), not the agent's: memory questions are skipped
        setup.append(f"Volatility cannot read the memory image: {memory_broken[:300]}")
    llm_with_tools, finalizer, model_name = model or make_model()
    results = {"name": spec["name"], "spec": spec["_path"], "run_id": run_id, "case_id": run_id,
               "client_id": case_config.client_id, "memory_image": case_config.memory_image,
               "model": model_name, "started": started.isoformat(), "triage": triage, "setup": setup,
               "questions": []}
    chat = []
    asked = [q for q in spec["questions"] if not only or q["id"] in only]
    if investigate_first and asked:              # not for a triage-only run (--questions none)
        log("\n[*] Investigation: one longer turn writes the case dossier the questions start from")
        note = "Triage results (Memory.* = memory image):\n" + "\n".join(f"  {line}" for line in triage) if triage else ""
        results["investigation"] = investigate(llm_with_tools, finalizer, note, log)
        inv = results["investigation"]
        log(f"[=] dossier {len(inv['dossier']):,} characters, {inv['steps']} steps, {inv['tokens_in']:,} tokens in, "
            f"{inv['seconds']} s" + (f" · {inv['error']}" if inv["error"] else ""))
        chat.append({"role": "assistant", "log": inv["log"],
                     "content": f"**Case dossier**\n\n{inv['dossier'] or '(none) ' + inv['error']}"})
    for question in asked:
        entry = {"id": question["id"], "ask": question["ask"]}
        if question.get("memory") and (not case_config.memory_image or memory_broken):
            entry["skipped"] = ("Volatility cannot read the memory image (setup)" if memory_broken
                                else "no memory image in this run")
            results["questions"].append(entry)
            continue
        log(f"\n[?] {question['id']}: {question['ask']}")
        entry.update(ask(question["ask"], llm_with_tools, finalizer, log))
        entry["score"] = score_answer(entry["answer"], question, spec, db=case_db)
        found = [f for f in entry["score"]["facts"] if f["scored"]]
        log(f"[=] facts {sum(f['found'] for f in found)}/{len(found)}, {entry['steps']} steps, "
            f"{entry['tokens_in']:,} tokens in, {entry['seconds']} s")
        results["questions"].append(entry)
        chat += [{"role": "user", "content": question["ask"]},
                 {"role": "assistant", "content": entry["answer"] or f"(no answer) {entry['error']}",
                  "log": entry["log"]}]
        conversation.save(run_id, chat, None)       # readable in the app as the run case's chat
    results["finished"] = datetime.now(timezone.utc).isoformat()
    results["totals"] = totals(results["questions"], results.get("investigation"))
    paths = save(results, out_dir)
    if results["totals"]["facts_total"]:
        log(f"\n[*] Score {results['totals']['score_percent']}%: {paths[1]}")
    else:
        log(f"\n[*] No answer key yet: answers saved in {paths[0]} (score them later with the 'score' command)")
    return results


RAW_CHARS = 1500


def evidence_dump(results_path: str, out_path: str = None) -> str:
    """
    For building an answer key without trusting the agent: every evidence ID each answer cites,
    with the raw record behind it (as Velociraptor / Volatility returned it, from the run case's
    database) and the record's times. Claims are checked against these, not against the answer.
    Writes <run>.evidence.md next to the results unless out_path is given; returns the path.
    """
    from copilot import cases
    from copilot.citations import EVIDENCE_RE, FINDING_RE
    from copilot.database import case_db
    with open(results_path, encoding="utf-8") as f:
        results = json.load(f)
    cases.switch(results["case_id"])
    cases.consume_switch()
    lines = [f"# Evidence cited by {results['run_id']}", "",
             "Raw records behind every evidence ID the answers cite, from the run case's database. "
             "Check each claim against these, not against the answer's wording.", ""]
    dossier = (results.get("investigation") or {}).get("dossier")
    for entry in ([{"id": "dossier", "ask": "the investigation's case dossier", "answer": dossier}] if dossier else []) \
            + results["questions"]:
        answer = entry.get("answer") or ""
        lines += [f"## {entry['id']}: {entry['ask']}", ""]
        ids = list(dict.fromkeys(EVIDENCE_RE.findall(answer)))
        for finding_id in dict.fromkeys(FINDING_RE.findall(answer)):
            finding = case_db.find_finding(finding_id)
            if finding:
                lines.append(f"- finding `{finding_id}`: {finding.get('title')} (cites {finding.get('evidence_ids')})")
        for evidence_id in ids:
            record = case_db.get_event_detail(evidence_id)
            if not record:
                lines += [f"### `{evidence_id}`: NOT IN THE CASE", ""]
                continue
            times = ", ".join(f"{t['timestamp_utc'][:19]} ({t['timestamp_desc']})" for t in record["timestamps"][:6])
            raw = str(record.get("raw_data") or "")
            lines += [f"### `{evidence_id}` {record.get('source')}", "",
                      f"{record.get('description')}", "", f"Times: {times or 'none'}", "",
                      "~~~~", raw[:RAW_CHARS] + (" ..." if len(raw) > RAW_CHARS else ""), "~~~~", ""]
        if not ids:
            lines += ["(no evidence IDs cited)", ""]
    out_path = out_path or os.path.splitext(results_path)[0] + ".evidence.md"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out_path


def rescore(results_path: str, spec_path: str = None, out_dir: str = None) -> dict:
    """Scores saved answers again (e.g. after correcting the answer key). Citation checks are kept."""
    with open(results_path, encoding="utf-8") as f:
        results = json.load(f)
    spec = load_spec(spec_path or results["spec"])
    by_id = {q["id"]: q for q in spec["questions"]}
    # Runs saved before unfinished triage was waited for: the questions started without that data.
    running = [line.split(" -> ")[0] for line in results.get("triage") or []
               if re.search(r"-> (IN_PROGRESS|RUNNING|WAITING|UNRESPONSIVE)\b", line)]
    if running and not any("Triage still running" in s for s in results.get("setup") or []):
        results["setup"] = list(results.get("setup") or []) + [
            f"Triage still running when the questions started: {', '.join(running)}; the answers lack its data"]
    # Runs saved before setup problems were recorded: every memory triage plugin failed on symbols.
    memory_lines = [line for line in results.get("triage") or [] if line.startswith("Memory.")]
    if memory_lines and all("-> ERROR" in line for line in memory_lines) and \
            any("symbol table" in line for line in memory_lines) and not results.get("setup"):
        results["setup"] = ["Volatility cannot read the memory image (every memory triage plugin failed on symbols)"]
    for entry in results["questions"]:
        if results.get("setup") and by_id.get(entry["id"], {}).get("memory") and not entry.get("skipped") \
                and any("memory image" in s for s in results["setup"]):
            entry["skipped"] = "Volatility cannot read the memory image (setup)"
        if entry.get("skipped") or entry["id"] not in by_id:
            continue
        cites = dict((entry.get("score") or {}).get("citations") or {}) or None
        if cites:                 # the database check is kept; text-only checks are redone
            missing = [m for m in malformed_ids(entry.get("answer")) if m not in cites.get("evidence_invalid", [])]
            cites["evidence_invalid"] = list(cites.get("evidence_invalid", [])) + missing
            cites["evidence_cited"] = cites.get("evidence_cited", 0) + len(missing)
        entry["score"] = score_answer(entry.get("answer") or "", by_id[entry["id"]], spec, citations=cites)
    results["totals"] = totals(results["questions"], results.get("investigation"))
    save(results, out_dir or os.path.dirname(os.path.abspath(results_path)))
    return results


def clean(yes: bool = False, log=print) -> list:
    """Removes the benchmark run cases (bench-*) and their data."""
    from copilot.case_config import cases_dir
    from copilot.database import data_dir_for
    root = cases_dir()
    runs = sorted(d for d in (os.listdir(root) if os.path.isdir(root) else [])
                  if d.startswith(RUN_PREFIX) and os.path.isfile(os.path.join(root, d, "case.yaml")))
    for run_id in runs:
        case_file = os.path.join(root, run_id, "case.yaml")
        data = data_dir_for(case_file)
        log(f"{'Removing' if yes else 'Would remove'} {os.path.dirname(case_file)} and {data}")
        if yes:
            # The data inside the run's folder goes with it. A data folder elsewhere is removed only if it
            # is this run's own (with DFIR_CASE_DIR set, every case shares one folder).
            case_folder = os.path.abspath(os.path.dirname(case_file))
            inside = os.path.abspath(data).startswith(case_folder + os.sep)
            if not inside and os.path.basename(os.path.normpath(data)) == run_id:
                shutil.rmtree(data, ignore_errors=True)
            shutil.rmtree(case_folder, ignore_errors=True)
    if runs and not yes:
        log("Run again with --yes to remove them.")
    return runs


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m copilot.benchmark", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="run a benchmark")
    r.add_argument("spec")
    r.add_argument("--client", help="Velociraptor client ID of the image (C.xxxx)")
    r.add_argument("--memory-image", help="memory image name in memory.images_dir ('' for none)")
    r.add_argument("--from-case", help="copy collected data from this case instead of running triage")
    r.add_argument("--skip-triage", action="store_true")
    r.add_argument("--questions", help="comma-separated question IDs")
    r.add_argument("--out", default=RESULTS_DIR)
    r.add_argument("--no-image-check", action="store_true",
                   help="run even if the time-window triage finds nothing (wrong image?)")
    r.add_argument("--triage-wait", type=float, default=TRIAGE_WAIT_MINUTES,
                   help=f"minutes to wait for triage collections still running (default {TRIAGE_WAIT_MINUTES})")
    r.add_argument("--no-investigate", action="store_true",
                   help="ask the questions without the investigation turn and its case dossier first")
    s = sub.add_parser("score", help="score saved answers again")
    s.add_argument("results")
    s.add_argument("--spec")
    e = sub.add_parser("evidence", help="dump the raw records the answers cite (to build an answer key)")
    e.add_argument("results")
    c = sub.add_parser("clean", help="remove benchmark run cases")
    c.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            only = [q.strip() for q in args.questions.split(",")] if args.questions else None
            run(args.spec, args.client, args.memory_image, args.from_case, args.skip_triage, only, out_dir=args.out,
                image_check=not args.no_image_check, triage_wait=args.triage_wait,
                investigate_first=not args.no_investigate)
        elif args.command == "score":
            t = rescore(args.results, args.spec)["totals"]
            print(f"Score {t['score_percent']}%: facts {t['facts_found']}/{t['facts_total']}, "
                  f"times {t['times_ok']}/{t['times_total']}")
        elif args.command == "evidence":
            print(f"[*] Written: {evidence_dump(args.results)}")
        else:
            clean(args.yes)
    except Exception as e:
        if e.__class__.__name__ in ("BenchmarkError", "CaseError", "SchemaError", "MemoryAnalysisError"):
            print(f"[!] {e}")
            return 1
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
