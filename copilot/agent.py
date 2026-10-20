import getpass
import json
import re
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage
from copilot.tools import tools, tool_map

def trim_chat_history(chat_history: list, keep_last_turns: int = 3) -> list:
    """Prunes older ToolMessage outputs to save context window memory."""
    ai_message_count = sum(1 for m in chat_history if isinstance(m, AIMessage))
    if ai_message_count <= keep_last_turns:
        return chat_history

    turns_seen = 0
    for i in range(len(chat_history) - 1, -1, -1):
        msg = chat_history[i]
        if isinstance(msg, AIMessage):
            turns_seen += 1

        if turns_seen > keep_last_turns and isinstance(msg, ToolMessage):
            if msg.content != "[Truncated to save memory]":
                chat_history[i] = ToolMessage(
                    content="[Truncated to save memory]",
                    tool_call_id=msg.tool_call_id,
                    name=msg.name
                )
    return chat_history

_EVIDENCE_ID = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{16}(?![0-9A-Za-z])")   # as citations.EVIDENCE_RE

INTERRUPTED = ("[No result: this step was interrupted before the tool finished (e.g. the page was used while "
               "the agent worked). Run it again if it is still needed.]")


def repair_history(history: list) -> list:
    """
    Keeps the conversation valid for the model API: every tool call the agent made gets a result,
    and no tool result is left without its call. A turn cut short between the two (Streamlit stops
    a running script when the page is used; a crash) would otherwise make every later request fail.
    Repairs in place and returns the list.
    """
    fixed, pending, names = [], [], {}

    def answer_pending():
        fixed.extend(ToolMessage(content=INTERRUPTED, tool_call_id=i, name=names.get(i, "")) for i in pending)
        pending.clear()

    for msg in history:
        if isinstance(msg, ToolMessage):
            if msg.tool_call_id in pending:
                pending.remove(msg.tool_call_id)
                fixed.append(msg)
            continue                                   # a result without its call is dropped
        answer_pending()
        fixed.append(msg)
        if isinstance(msg, AIMessage) and msg.tool_calls:
            for call in msg.tool_calls:
                pending.append(call["id"])
                names[call["id"]] = call.get("name", "")
    answer_pending()
    history[:] = fixed
    return history


def status_line(summary: dict) -> str:
    """One-line, human readable result of a collection."""
    line = f"{summary.get('artifact')} -> {summary.get('state')}"
    if summary.get("time_window_applied"):
        line += f" (time window: {', '.join(summary['time_window_applied'])})"
    if summary.get("state") == "FINISHED" and "rows_collected_by_velociraptor" in summary:
        line += (f": Velociraptor rows {summary.get('rows_collected_by_velociraptor')}, "
                 f"read {summary.get('rows_read')}, new {summary.get('new_rows_ingested')}")
    elif summary.get("state") == "FINISHED":
        line += f": rows {summary.get('rows_read')}, new {summary.get('new_rows_ingested')}"
        if summary.get("duplicates_dropped"):
            line += f", {summary['duplicates_dropped']} repeated rows dropped"
        if summary.get("seconds") is not None:
            line += f" ({summary['seconds']} s)"
    if summary.get("error"):
        line += f": {summary['error']}"
    if summary.get("note"):
        line += f"\n       {summary['note']}"
    for log in summary.get("velociraptor_log", []):
        line += f"\n       log | {log}"
    return line


def auto_collect(case_config, collect=None, steps: list = None) -> list:
    """
    Runs the case's triage collections (or the given steps of it) directly (no LLM involved) and
    returns one summary per artifact. Failures are reported, not raised.
    """
    from copilot import collection
    collect = collect or collection.collect
    summaries = []
    for step in case_config.collection_plan if steps is None else steps:
        artifact, params = step["artifact"], step["parameters"]
        print(f"[*] Collecting {artifact}" + (f" {json.dumps(params)}" if params else "") + " ...")
        try:
            summary = collect(artifact, params)
        except collection.CollectionError as e:
            summary = {"artifact": artifact, "state": "NOT_STARTED", "error": str(e)}
        print(f"    {status_line(summary)}")
        summaries.append(summary)
    return summaries


def _confirm(request: dict) -> bool:
    """CLI approval for anything the agent wants to change (collections, findings, cases)."""
    from copilot import approvals
    print(f"\n[?] The agent wants to {approvals.ACTIONS.get(request['kind'], request['kind'])}:")
    print(f"    {request['summary']}")
    shown = request["details"].get("params") or request["details"].get("options")
    if request["kind"] in ("collect", "memory") and shown:
        print(f"    parameters: {json.dumps(shown)}")
    answer = input("    Allow? (y/N): ").strip().lower()
    return answer in ("y", "yes")


def run_agent_loop():
    from copilot import collection
    from copilot import llm as llm_config
    from copilot.case_config import case_config
    from copilot.prompts import build_system_prompt

    api_key = None
    if llm_config.needs_user_key():
        api_key = getpass.getpass("Please enter the API key for the LLM endpoint: ")
    elif llm_config.is_local():
        print(f"[*] Local model '{llm_config.model_name()}' at {llm_config.base_url()}")
    llm = llm_config.make_llm(api_key)
    llm_with_tools = llm.bind_tools(tools)
    # Same model, but not allowed to call tools: used to wrap up before the budget runs out.
    finalizer = llm.bind_tools(tools, tool_choice="none")

    from copilot import cases, commands, conversation
    from copilot.database import case_db
    chat_history = []
    state = {"case": None, "ui": []}

    def open_chat():
        """Loads the active case's saved conversation (the agent gets its memory back)."""
        state["case"] = cases.current_id()
        from copilot import config_check
        for problem in config_check.case_problems(case_config):
            print(f"[!] case settings: {problem}")
        state["ui"], history = conversation.load(state["case"], build_system_prompt(case_config))
        chat_history[:] = history
        if len(history) > 1:
            print(f"[*] Restored the conversation of case '{state['case']}' ({len(state['ui'])} messages). "
                  f"Type /new to start over.")

    def save():
        conversation.save(state["case"], state["ui"], chat_history)

    def follow_case():
        """Keeps the conversation with its case when the active case or its settings change."""
        cases.consume_switch()
        if state["case"] != cases.current_id():
            save()
            print(f"\n=== Now in case '{cases.current_id()}': {case_config.case_name} "
                  f"(client {case_config.client_id or 'not set'}); '{state['case']}' was saved ===")
            open_chat()
            hint = cases.legacy_data_hint()
            if hint:
                print(f"[!] {hint}")
        if cases.consume_settings_change():
            chat_history[0] = SystemMessage(content=build_system_prompt(case_config))
            print("\n[*] Case settings updated.")

    def turn(text: str, show_user: bool = True):
        from copilot import citations
        from copilot.knowledge import with_playbooks
        chat_history.append(HumanMessage(content=with_playbooks(text) if show_user else text))
        answer = run_turn(llm_with_tools, chat_history, MAX_STEPS, usage, case_config.max_tokens_per_turn, finalizer)
        found = citations.cited(answer, case_db, case_config)
        if found["evidence"] or found["findings"]:
            print(f"\n[*] Cited in this answer ({citations.summary(found)}):\n{citations.as_text(found)}")
        if show_user:
            state["ui"].append({"role": "user", "content": text})
        state["ui"].append({"role": "assistant", "content": answer or "No answer."})
        save()            # saved with the case it was asked in, even if the agent switched cases
        follow_case()

    def investigate(extra: str = ""):
        """The investigation turn (copilot/dossier.py): writes the case dossier every question starts from."""
        from copilot import dossier
        print("\n[*] Investigating the whole case (one longer agent turn that writes the case dossier) ...")
        try:
            entry = dossier.investigate(llm_with_tools, finalizer, usage, extra=extra)
        except dossier.DossierError as e:
            print(f"\n[!] {e}")
            return
        chat_history[0] = SystemMessage(content=build_system_prompt(case_config))
        state["ui"].append({"role": "assistant", "content": f"**Case dossier**\n\n{entry['text']}"})
        save()
        print(f"\n[*] Dossier saved ({entry['steps']} steps, {entry['tokens']:,} tokens). "
              f"Every question now starts from it; /investigate writes it again.")

    from copilot import approvals
    approvals.ASK = _confirm
    try:
        approvals.ACTOR = getpass.getuser()  # recorded with each approval in the audit log
    except Exception:                        # no login name in some containers
        approvals.ACTOR = None
    MAX_STEPS = case_config.max_steps
    usage = TokenUsage()

    print("=" * 60)
    print("  DFIR Copilot v2 — Database-Backed Analysis")
    print(f"  Case database: {case_db.db_path}")
    print(f"  Scope file: {case_config.path} {'(Loaded)' if case_config.data else '(Not Found/Empty)'}")
    print(f"  Evidence client: {case_config.client_id or '(not set)'}")
    print(f"  Case: {cases.current_id()}  ·  /cases to list, /case <id> to switch")
    print("  Type 'exit' to quit, 'report' for findings, 'retract <id> <reason>' to drop one")
    print("=" * 60)

    hint = cases.legacy_data_hint()
    if hint:
        print(f"\n[!] {hint}")
    from copilot import config_check
    for problem in config_check.server_problems():
        print(f"[!] server settings: {problem}")
    open_chat()

    summaries = None
    if case_config.client_id_error:
        print(f"\n[!] {case_config.client_id_error}")

    # Prompt user for auto-collection
    elif input("\nDo you want to run the initial auto-collection based on case.yaml? (y/n) [y]: ").lower() in ['', 'y', 'yes']:
        print("\n[*] Starting automatic collection...")
        summaries = auto_collect(case_config)
    if case_config.memory_image and input(f"\nRun the memory triage (Volatility) on {case_config.memory_image}? "
                                          f"(y/n) [y]: ").lower() in ['', 'y', 'yes']:
        from copilot import memory
        results = memory.triage(progress=lambda plugin: print(f"[*] Volatility {plugin} ..."))
        for summary in results:
            print(f"    {status_line(summary)}")
        summaries = (summaries or []) + results
    if summaries and all(s.get("state") == "NOT_STARTED" for s in summaries):
        print("\n[!] No collection could be started, so the agent was not run on them. "
              "Fix the error above (Velociraptor connection, client ID, artifact names), then retry.")
    elif summaries:
        from copilot.dossier import budget, triage_note
        if input(f"\nOptional: investigate the case now? One longer agent turn (up to {budget()[0]} steps) writes "
                 f"the case dossier every question starts from; /investigate runs it later. (y/n) [y]: "
                 ).lower() in ['', 'y', 'yes']:
            investigate(triage_note(summaries))

    while True:
        user_input = input("\nInvestigator> ")
        if user_input.lower() in ['quit', 'exit']:
            break

        if user_input.strip().lower() == "/new":
            conversation.clear(state["case"])
            open_chat()
            print("[*] New conversation for this case (data and findings are kept).")
            continue

        if user_input.strip().lower() == commands.INVESTIGATE:
            investigate()
            continue

        reply = commands.handle(user_input)
        if reply is not None:
            print(f"\n{reply}")
            follow_case()
            continue

        if user_input.lower().startswith('retract '):
            from copilot.database import case_db
            parts = user_input.split(maxsplit=2)
            reason = parts[2] if len(parts) > 2 else "Retracted by the investigator."
            found = case_db.retract_finding(parts[1], reason) if len(parts) > 1 else {}
            print(f"  Retracted: {found['title']}" if found else "  No unique finding with that ID.")
            continue

        if user_input.lower() == 'report':
            from copilot.database import case_db
            findings = case_db.get_findings()
            stats = case_db.get_stats()
            print(f"\n{'='*60}")
            print(f"  CASE SUMMARY")
            print(f"  Records: {stats['total_records']} ({stats['undated_records']} without timestamps)")
            print(f"  Timeline Events: {stats['timeline_events']}")
            print(f"  Time Range: {stats['earliest']} → {stats['latest']}")
            print(f"  Findings: {len(findings)}")
            print(f"{'='*60}")
            for f in findings:
                print(f"\n  [{(f['confidence'] or 'unknown').upper()}] {f['title']}  (id {f['finding_id']})")
                print(f"  {f['description']}")
                if f['mitre_technique']:
                    print(f"  MITRE: {f['mitre_technique']}")
            continue

        turn(user_input)


class TokenUsage:
    """
    Counts tokens per turn and for the session. Uses the usage the API reports; when an
    endpoint reports none (common for local model servers), estimates ~4 characters per
    token so the per-turn budget still works.
    """

    def __init__(self):
        self.session_input = self.session_output = 0
        self.turn_input = self.turn_output = 0
        self.estimated = False

    def start_turn(self):
        self.turn_input = self.turn_output = 0

    def add(self, response, prompt_chars: int = 0):
        meta = getattr(response, "usage_metadata", None) or {}
        tokens_in, tokens_out = meta.get("input_tokens", 0), meta.get("output_tokens", 0)
        if not (tokens_in or tokens_out):
            self.estimated = True
            out_chars = len(str(response.content or "")) + len(json.dumps(getattr(response, "tool_calls", None) or [],
                                                                           default=str))
            tokens_in, tokens_out = prompt_chars // 4, out_chars // 4
        self.turn_input += tokens_in
        self.turn_output += tokens_out
        self.session_input += tokens_in
        self.session_output += tokens_out

    @property
    def turn_total(self) -> int:
        return self.turn_input + self.turn_output

    def summary(self) -> str:
        return (f"[tokens] this turn: {self.turn_input:,} in / {self.turn_output:,} out"
                f" | session: {self.session_input + self.session_output:,}"
                + (" (estimated: the model doesn't report usage)" if self.estimated else ""))


def _prompt_chars(history) -> int:
    return sum(len(str(m.content or "")) + len(json.dumps(getattr(m, "tool_calls", None) or [], default=str))
               for m in history)


WRAP_UP_AT = 0.8  # share of the token budget after which the agent must answer
WRAP_UP_PROMPT = (
    "[Copilot] The {what} for this question is used up. Do not call any tools. "
    "Answer now with what you have: findings so far (with evidence IDs and UTC times), "
    "what is still unverified, and the next steps you recommend."
)


def _wrap_up(llm_with_tools, finalizer, chat_history, usage, what: str) -> str:
    """Makes the model answer without tools (the finalizer), so a turn never ends with nothing."""
    chat_history.append(HumanMessage(content=WRAP_UP_PROMPT.format(what=what)))
    trim_chat_history(chat_history)
    try:
        response = finalizer.invoke(chat_history)
    except Exception:
        # Some local servers don't support tool_choice="none": ask the normal model
        # and keep only its text (unanswered tool calls would break the next request).
        response = llm_with_tools.invoke(chat_history)
        usage.add(response, _prompt_chars(chat_history))
        response = AIMessage(content=answer_text(response))
    else:
        usage.add(response, _prompt_chars(chat_history))
    chat_history.append(response)
    return answer_text(response) or "(The model returned no text.)"


def answer_text(response) -> str:
    """Text content of a model response (string or content blocks)."""
    if isinstance(response.content, list):
        return "\n".join(b["text"] if isinstance(b, dict) else str(b) for b in response.content
                         if isinstance(b, str) or (isinstance(b, dict) and b.get("type") == "text"))
    return str(response.content or "")


def _print_event(kind: str, payload):
    """CLI renderer for run_turn events."""
    if kind == "tool":
        print(f"[*] Agent is running tool: {payload}...")
    elif kind == "collection":
        print(f"    {payload}")
    elif kind == "notice":
        print(f"\n[!] {payload}")
    elif kind == "answer":
        print("\n### Agent Response ###\n")
        print(payload)
    elif kind == "usage":
        print(f"\n{payload}")


def run_turn(llm_with_tools, chat_history, max_steps, usage: TokenUsage = None, max_tokens: int = None,
             finalizer=None, emit=_print_event) -> str:
    """
    One investigator turn: the tool-calling loop within step and token limits, shared by the
    CLI and Streamlit. Progress is reported through emit(kind, payload) with kind in
    tool | collection | notice | answer | usage. With a `finalizer` (the model without tools)
    the agent is made to answer at 80% of the token budget instead of stopping with nothing.
    Returns the answer text ("" if none).
    """
    usage = usage or TokenUsage()
    usage.start_turn()
    seen_ids = set()          # evidence IDs in this turn's tool results (older ones get trimmed)
    answer = ""
    answered = False
    repair_history(chat_history)               # e.g. a previous turn that was cut short
    try:
        step_count = 0
        while step_count < max_steps:
            if max_tokens and finalizer is not None and usage.turn_total >= WRAP_UP_AT * max_tokens:
                emit("notice", f"{usage.turn_total:,} of {max_tokens:,} tokens used: asking the agent to wrap up.")
                answer, answered = _wrap_up(llm_with_tools, finalizer, chat_history, usage, "token budget"), True
                emit("answer", answer)
                break
            if max_tokens and usage.turn_total >= max_tokens:
                emit("notice", f"Token budget for this turn reached ({usage.turn_total:,} >= {max_tokens:,}). "
                               f"Halting; ask a narrower question or raise agent.max_tokens_per_turn.")
                break
            step_count += 1
            trim_chat_history(chat_history)

            response = llm_with_tools.invoke(chat_history)
            usage.add(response, _prompt_chars(chat_history))
            chat_history.append(response)

            if not response.tool_calls:
                answer, answered = answer_text(response), True
                emit("answer", answer)
                break

            for tool_call in response.tool_calls:
                emit("tool", tool_call["name"])
                try:
                    tool_fn = tool_map[tool_call["name"]]
                    tool_output = tool_fn.invoke(tool_call["args"])
                except Exception as e:
                    tool_output = f"Tool execution failed: {e}"
                if tool_call["name"] in ("collect_artifact", "check_collection"):
                    try:
                        emit("collection", status_line(json.loads(tool_output)))
                    except (ValueError, TypeError):
                        emit("collection", str(tool_output)[:300])

                seen_ids.update(_EVIDENCE_ID.findall(str(tool_output)))
                chat_history.append(ToolMessage(
                    content=str(tool_output),
                    tool_call_id=tool_call["id"],
                    name=tool_call["name"]
                ))

        if not answered and step_count >= max_steps:
            if finalizer is not None:
                emit("notice", f"All {max_steps} tool steps used: asking the agent to wrap up.")
                answer, answered = _wrap_up(llm_with_tools, finalizer, chat_history, usage, "tool-step budget"), True
                emit("answer", answer)
            else:
                emit("notice", "Agent reached maximum tool steps. Halting.")

    except Exception as e:
        emit("notice", f"Agent Error: {e}")
    finally:
        # Also when Streamlit stops the script mid-turn (its exceptions are not Exceptions):
        # the saved conversation must stay valid.
        repair_history(chat_history)
    answer = _repair_citations(answer, chat_history, seen_ids)
    emit("usage", usage.summary())
    return answer


def _repair_citations(answer: str, chat_history: list, seen_ids: set = ()) -> str:
    """Puts back evidence IDs the model garbled when copying them from its tool results."""
    if not answer:
        return answer
    from copilot.citations import repair_ids
    from copilot.database import case_db
    seen = set(seen_ids) | {i for m in chat_history if isinstance(m, ToolMessage)
                            for i in _EVIDENCE_ID.findall(str(m.content))}
    try:
        fixed, fixes = repair_ids(answer, seen, case_db)
    except Exception:            # never lose an answer over a citation check
        return answer
    if fixes:
        for message in reversed(chat_history):       # the agent remembers the corrected answer too
            if isinstance(message, AIMessage) and answer_text(message) == answer:
                message.content = fixed
                break
    return fixed


def _process_turn(llm_with_tools, chat_history, max_steps, usage: TokenUsage = None, max_tokens: int = None,
                  finalizer=None):
    """CLI turn (prints as it goes). Kept for the CLI loop and tests."""
    usage = usage or TokenUsage()
    run_turn(llm_with_tools, chat_history, max_steps, usage, max_tokens, finalizer)
    return usage
