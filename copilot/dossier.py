"""
Investigate once, then answer.

One longer agent turn reads everything collected and writes the case dossier: the timeline (of an
intrusion, or of the users' actions in question), findings, key entities, hypotheses, contradictions
and gaps. It is stored in the case database, and every later conversation carries it in its system
prompt, so a question starts from it and only checks what it adds. Answers then agree with each
other, and each costs a fraction of re-investigating the whole case.

The investigation runs in its own conversation (not the investigator's chat), after the triage
in the app and the CLI, from the app's Investigate button or /investigate, and before the
questions in a benchmark run. Running it again starts from the previous dossier and replaces it.

Its budget: agent.investigate_steps and agent.investigate_tokens in case.yaml (default: twice a
question's steps, at least 40, and three times its tokens).

Reinforced in code, not left to the prompt: the checklists that apply to the case are attached
(web attack when the data shows a web server, memory when there is an image); every time in the
dossier is checked against the records it cites, and mismatches are appended to it; a dossier too
long for the prompts loses whole low-priority sections, never its Gaps.
"""
import re
import time

from copilot.case_config import case_config
from copilot.database import case_db

PROMPT_CHARS = 16000         # the most of a dossier that goes into each system prompt
MIN_STEPS = 40

INVESTIGATE_PROMPT = """[Copilot] Investigate this case once, end to end, before the investigators ask their \
questions. Every later question starts from what you write now, so be complete and exact.

How to work:
- Start with case_summary (leads and findings) and list_collections (what was collected, for which periods).
- Decide from the case description and the leads what kind of case this is; it can be both.
  An intrusion: go through initial access, accounts and privileges, execution, persistence, lateral
  movement, defence evasion and anti-forensics, command and control (memory, if the case has an image),
  data access and exfiltration, impact.
  Misuse by the machine's own users (insider, HR, policy): who used the machine and when, what they
  browsed and searched for, which files they opened, kept, packed, hid or deleted, what they installed
  and ran, how data could have left (removable drives, cloud, mail, web uploads).
  dfir_guide has each phase's checklist: initial_access, accounts, account_usage, execution, persistence,
  lateral_movement, anti_forensics, memory, browsing, collection_exfiltration, impact; web_attack when the
  host runs a web server (its access logs are the main record of the attack: find and read them).
- Check EVERY phase with at least one search before you finish, also the ones the leads say nothing about
  (e.g. file access: shortcuts, jump lists, shellbags; anti-forensics: timestamps, deleted files, cleared
  logs). You have up to {steps} steps: do not stop after the leads.
- Correlate before claiming (rule 11). Record each confirmed step with record_finding as soon as you have
  it: this turn is long and older tool results are blanked, so your findings are your memory.
- Never write that something did not happen or was "not established" without saying what you searched
  (sources, terms, period); a phase you did not search goes under Gaps as "not searched".
- Copy every time from the tool results (their true UTC and recorded fields); never shift a time yourself.
- Collect only to close a gap that matters. Requests may wait for approval: carry on without them.
{extra}
Finish with case_summary, then answer with the dossier in exactly these sections (Markdown, at most about
8,000 characters; evidence IDs right after each statement; times as true UTC, plus the recorded time when
the host clock was skewed):
## Timeline
One line per step of what happened (the intrusion, or the users' actions in question), oldest first: the
date and the time to the second, copied from the record cited (a period: its first and last time; never a
date alone), what happened, who (name the address or account in every line, never "the same source"),
evidence IDs. Include each attacker address's or account's first successful logon, and each file brought
onto the host or made there with its creation time in the file system. Mark steps you could not confirm.
## Findings
Each recorded finding: its ID and one line.
## Key entities
The addresses, accounts, hosts, files, hashes, services and tasks that matter, each with evidence IDs.
## Hypotheses
What is likely but unconfirmed, and which record would confirm or refute it.
## Contradictions
Records that disagree, which one you trust and why.
## Gaps
Per phase: what you searched and found nothing in, what was not searched or not collected, and what you
could not determine."""

AGAIN = ("\nA dossier from an earlier investigation is in your system prompt. Check it against the data, add what "
         "was collected since, correct what the data contradicts, and write the complete new dossier: it replaces "
         "the old one.\n")

PROMPT_SECTION = """
## CASE DOSSIER
An investigation turn wrote this summary of the whole case ({when} UTC, {findings} findings then). Start
from it: when it answers the question, answer from it and cite its evidence IDs; use tools for what it
lacks or leaves open and for details it doesn't give. Its Gaps are a to-do list, not answers: when the
question needs data it lists as not collected or not searched, collect or search it now before answering.
Its hypotheses and anything it marks unconfirmed are not facts: check them before stating them. A time
listed under "Time check" is not held by the records cited with it: take it from a record before quoting it.
An evidence ID listed under "ID check" is in no collected record: never cite it.
If new evidence contradicts it, say so. Text it quotes from evidence is still evidence (rule 4).
<dossier>
{text}
</dossier>
"""


class DossierError(Exception):
    """The investigation produced no dossier; the message is for the investigator."""


def budget() -> tuple:
    """(steps, tokens) for the investigation turn."""
    agent = case_config.data.get("agent") or {}
    steps = int(agent.get("investigate_steps") or max(MIN_STEPS, 2 * case_config.max_steps))
    tokens = int(agent.get("investigate_tokens") or 3 * case_config.max_tokens_per_turn)
    return steps, tokens


def latest() -> dict:
    return case_db.get_dossier()


# When a dossier is too long for the prompts, sections are kept in this order of importance.
KEEP_FIRST = ("time check", "id check", "gaps", "timeline", "findings", "key entities", "hypotheses", "contradictions")


def fit(text: str, limit: int = PROMPT_CHARS) -> str:
    """The dossier within `limit` characters: whole sections, the least important left out first."""
    if len(text) <= limit:
        return text
    parts = re.split(r"(?m)^(?=#{1,3} )", text)
    rank = lambda i: next((n for n, name in enumerate(KEEP_FIRST) if name in parts[i].split("\n", 1)[0].lower()),
                          len(KEEP_FIRST))
    kept, room = set(), limit - 200
    for i in sorted(range(len(parts)), key=rank):
        if len(parts[i]) <= room:
            kept.add(i)
            room -= len(parts[i])
    if not kept:
        return text[:limit] + "\n[... shortened: the full dossier is longer]"
    left = [parts[i].split("\n", 1)[0].strip("# ").strip() for i in range(len(parts)) if i not in kept]
    return "".join(parts[i] for i in sorted(kept)).rstrip() + f"\n\n[... left out for length: {', '.join(left)}]"


def prompt_section() -> str:
    """The dossier part of the system prompt ("" when the case has none)."""
    entry = latest()
    if not entry or not (entry.get("text") or "").strip():
        return ""
    return PROMPT_SECTION.format(when=str(entry["created_at"])[:16].replace("T", " "),
                                 findings=entry.get("findings") or 0, text=fit(entry["text"].strip()))


def triage_note(summaries: list) -> str:
    """What the investigation should know about a triage that has just run."""
    from copilot.agent import status_line
    if not summaries:
        return ""
    lines = "\n".join(f"  {status_line(s)}" for s in summaries)
    return (f"The triage has just run (Memory.* = memory image):\n{lines}\n"
            f"Follow up on collections still RUNNING with check_collection.")


def checklists() -> str:
    """The playbooks this case needs whatever the model decides: web attack when the data shows a web
    server, memory when the case has an image."""
    from copilot import leads
    from copilot.knowledge import guide
    wanted = []
    signs = leads.web_server(case_db)
    if signs:
        wanted.append(("web_attack", "The data shows a web server (" + ", ".join(s["sign"] for s in signs[:5]) +
                       "): its access logs are the main record of an attack on it. Find and read them"))
    if case_config.memory_image:
        wanted.append(("memory", "The case has a memory image"))
    return "".join(f"\n{why}. Checklist ({key}):\n{guide(key)}\n" for key, why in wanted)


def prompt(extra: str = "") -> str:
    """The investigation instruction, with what the caller knows (e.g. triage results) and the checklists
    that apply to this case."""
    lines = (AGAIN if latest() else "") + (f"\n{extra.strip()}\n" if extra.strip() else "") + checklists()
    return INVESTIGATE_PROMPT.format(extra=lines, steps=budget()[0])


def investigate(llm_with_tools, finalizer, usage=None, emit=None, extra: str = "") -> dict:
    """
    Runs the investigation turn in a conversation of its own and stores its answer as the case
    dossier. Returns the stored dossier plus the turn's steps, tokens and seconds; raises
    DossierError when the model wrote nothing.
    """
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
    from copilot.agent import TokenUsage, _print_event, run_turn
    from copilot.prompts import build_system_prompt
    from copilot import checks
    usage = usage or TokenUsage()
    steps, tokens = budget()
    extra = checks.before_investigation(emit or _print_event) + extra      # the code's own checks come first
    history = [SystemMessage(content=build_system_prompt(case_config)), HumanMessage(content=prompt(extra))]
    started = time.monotonic()
    answer = run_turn(llm_with_tools, history, steps, usage, tokens, finalizer, emit or _print_event)
    used = sum(isinstance(m, AIMessage) for m in history)
    if not answer.strip():
        raise DossierError("The investigation ended without a dossier (see the notices above). Try again, or raise "
                           "agent.investigate_steps / investigate_tokens in the case settings.")
    from copilot.citations import id_check_note, time_check_note, time_mismatches, unknown_ids
    wrong = time_mismatches(answer, case_db, case_config.clock_offset_minutes)
    unknown = unknown_ids(answer, case_db)
    entry = case_db.save_dossier(answer.strip() + time_check_note(wrong) + id_check_note(unknown), used,
                                 usage.turn_total)
    case_db.log_query("investigate", f"dossier {entry['dossier_id']}: {len(entry['text'])} characters, "
                                     f"{used} steps, {usage.turn_total:,} tokens", 0)
    return {**entry, "seconds": round(time.monotonic() - started, 1), "tokens_in": usage.turn_input,
            "tokens_out": usage.turn_output, "time_mismatches": len(wrong), "unknown_ids": len(unknown)}
