import getpass
import json
import os
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

def status_line(summary: dict) -> str:
    """One-line, human readable result of a collection."""
    line = f"{summary.get('artifact')} -> {summary.get('state')}"
    if summary.get("time_window_applied"):
        line += f" (time window: {', '.join(summary['time_window_applied'])})"
    if summary.get("state") == "FINISHED":
        line += (f": Velociraptor rows {summary.get('rows_collected_by_velociraptor')}, "
                 f"read {summary.get('rows_read')}, new {summary.get('new_rows_ingested')}")
    if summary.get("error"):
        line += f": {summary['error']}"
    if summary.get("note"):
        line += f"\n       {summary['note']}"
    for log in summary.get("velociraptor_log", []):
        line += f"\n       log | {log}"
    return line


def auto_collect(case_config, collect=None) -> list:
    """
    Runs the case's triage collections directly (no LLM involved) and returns
    one summary per artifact. Failures are reported, not raised.
    """
    from copilot import collection
    collect = collect or collection.collect
    summaries = []
    for step in case_config.collection_plan:
        artifact, params = step["artifact"], step["parameters"]
        print(f"[*] Collecting {artifact}" + (f" {json.dumps(params)}" if params else "") + " ...")
        try:
            summary = collect(artifact, params)
        except collection.CollectionError as e:
            summary = {"artifact": artifact, "state": "NOT_STARTED", "error": str(e)}
        print(f"    {status_line(summary)}")
        summaries.append(summary)
    return summaries


def _confirm_collection(artifact: str, params: dict) -> bool:
    """CLI approval for collections the agent asks for."""
    print(f"\n[?] The agent wants to collect {artifact}")
    if params:
        print(f"    parameters: {json.dumps(params)}")
    answer = input("    Allow? (y/N): ").strip().lower()
    return answer in ("y", "yes")


def run_agent_loop():
    from copilot import collection
    from copilot.case_config import case_config
    from copilot.llm import make_llm
    from copilot.prompts import build_system_prompt

    api_key = os.environ.get("OPENAI_API_KEY") or getpass.getpass("Please enter your OpenAI API Key: ")
    llm = make_llm(api_key)
    llm_with_tools = llm.bind_tools(tools)
    # Same model, but not allowed to call tools: used to wrap up before the budget runs out.
    finalizer = llm.bind_tools(tools, tool_choice="none")

    chat_history = [SystemMessage(content=build_system_prompt(case_config))]
    collection.CONFIRM = _confirm_collection
    MAX_STEPS = case_config.max_steps
    usage = TokenUsage()

    print("=" * 60)
    print("  DFIR Copilot v2 — Database-Backed Analysis")
    print("  Case database: case_data/case.db")
    print(f"  Scope file: {case_config.path} {'(Loaded)' if case_config.data else '(Not Found/Empty)'}")
    print(f"  Evidence client: {case_config.client_id or '(not set)'}")
    print("  Type 'exit' to quit, 'report' for findings summary")
    print("=" * 60)

    summaries = None
    if case_config.client_id_error:
        print(f"\n[!] {case_config.client_id_error}")

    # Prompt user for auto-collection
    elif input("\nDo you want to run the initial auto-collection based on case.yaml? (y/n) [y]: ").lower() in ['', 'y', 'yes']:
        print("\n[*] Starting automatic collection...")
        summaries = auto_collect(case_config)
    if summaries and all(s.get("state") == "NOT_STARTED" for s in summaries):
        print("\n[!] No collection could be started, so the agent was not run on them. "
              "Fix the error above (Velociraptor connection, client ID, artifact names), then retry.")
    elif summaries:
        auto_prompt = (
            "The initial collection has been run for you. Results per artifact:\n"
            f"{json.dumps(summaries, indent=2)}\n"
            "Follow up on any collection that is still RUNNING with check_collection. "
            "If IOCs are defined in the case, search for them. "
            "If an incident time window is defined, query the timeline for that window."
        )
        chat_history.append(HumanMessage(content=auto_prompt))
        _process_turn(llm_with_tools, chat_history, MAX_STEPS, usage, case_config.max_tokens_per_turn, finalizer)

    while True:
        user_input = input("\nInvestigator> ")
        if user_input.lower() in ['quit', 'exit']:
            break

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
                print(f"\n  [{(f['confidence'] or 'unknown').upper()}] {f['title']}")
                print(f"  {f['description']}")
                if f['mitre_technique']:
                    print(f"  MITRE: {f['mitre_technique']}")
            continue

        chat_history.append(HumanMessage(content=user_input))
        _process_turn(llm_with_tools, chat_history, MAX_STEPS, usage, case_config.max_tokens_per_turn, finalizer)


class TokenUsage:
    """Counts tokens reported by the LLM API, per turn and for the whole session."""

    def __init__(self):
        self.session_input = self.session_output = 0
        self.turn_input = self.turn_output = 0

    def start_turn(self):
        self.turn_input = self.turn_output = 0

    def add(self, response):
        meta = getattr(response, "usage_metadata", None) or {}
        self.turn_input += meta.get("input_tokens", 0)
        self.turn_output += meta.get("output_tokens", 0)
        self.session_input += meta.get("input_tokens", 0)
        self.session_output += meta.get("output_tokens", 0)

    @property
    def turn_total(self) -> int:
        return self.turn_input + self.turn_output

    def summary(self) -> str:
        return (f"[tokens] this turn: {self.turn_input:,} in / {self.turn_output:,} out"
                f" | session: {self.session_input + self.session_output:,}")


WRAP_UP_AT = 0.8  # share of the token budget after which the agent must answer
WRAP_UP_PROMPT = (
    "[Copilot] The token budget for this question is nearly used. Do not call any tools. "
    "Answer now with what you have: findings so far (with evidence IDs and UTC times), "
    "what is still unverified, and the next steps you recommend."
)


def _print_answer(response):
    print("\n### Agent Response ###\n")
    if isinstance(response.content, list):
        for block in response.content:
            if isinstance(block, dict) and block.get("type") == "text":
                print(block["text"])
            elif isinstance(block, str):
                print(block)
    else:
        print(response.content)


def _process_turn(llm_with_tools, chat_history, max_steps, usage: TokenUsage = None, max_tokens: int = None,
                  finalizer=None):
    """
    Processes a single conversational turn with tool calling loop, within step and token
    limits. With a `finalizer` (the model without tools), the agent is made to answer
    once 80% of the token budget is used, instead of stopping with nothing.
    """
    usage = usage or TokenUsage()
    usage.start_turn()
    answered = False
    try:
        step_count = 0
        while step_count < max_steps:
            if max_tokens and finalizer is not None and usage.turn_total >= WRAP_UP_AT * max_tokens:
                print(f"\n[!] {usage.turn_total:,} of {max_tokens:,} tokens used: asking the agent to wrap up.")
                chat_history.append(HumanMessage(content=WRAP_UP_PROMPT))
                trim_chat_history(chat_history)
                response = finalizer.invoke(chat_history)
                usage.add(response)
                chat_history.append(response)
                _print_answer(response)
                answered = True
                break
            if max_tokens and usage.turn_total >= max_tokens:
                print(f"\n[!] Token budget for this turn reached ({usage.turn_total:,} >= {max_tokens:,}). "
                      f"Halting; ask a narrower question or raise agent.max_tokens_per_turn.")
                break
            step_count += 1
            trim_chat_history(chat_history)

            response = llm_with_tools.invoke(chat_history)
            usage.add(response)
            chat_history.append(response)

            if not response.tool_calls:
                answered = True
                _print_answer(response)
                break

            for tool_call in response.tool_calls:
                print(f"[*] Agent is running tool: {tool_call['name']}...")
                try:
                    tool_fn = tool_map[tool_call["name"]]
                    tool_output = tool_fn.invoke(tool_call["args"])
                except Exception as e:
                    tool_output = f"Tool execution failed: {e}"
                if tool_call["name"] in ("collect_artifact", "check_collection"):
                    try:
                        print(f"    {status_line(json.loads(tool_output))}")
                    except (ValueError, TypeError):
                        print(f"    {str(tool_output)[:300]}")

                chat_history.append(ToolMessage(
                    content=str(tool_output),
                    tool_call_id=tool_call["id"],
                    name=tool_call["name"]
                ))

        if not answered and step_count >= max_steps:
            print("\n[!] Agent reached maximum tool steps. Halting.")

    except Exception as e:
        print(f"Agent Error: {e}")
    print(f"\n{usage.summary()}")
    return usage
