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

def auto_collect(case_config, collect=None) -> list:
    """
    Runs the case's initial collections directly (no LLM involved) and returns
    one summary per artifact. Failures are reported, not raised.
    """
    from copilot import collection
    collect = collect or collection.collect
    summaries = []
    for artifact in case_config.artifacts_to_collect:
        print(f"[*] Collecting {artifact} ...")
        try:
            summary = collect(artifact)
        except collection.CollectionError as e:
            summary = {"artifact": artifact, "state": "NOT_STARTED", "error": str(e)}
        print(f"    -> {summary.get('state')}"
              + (f", {summary['new_rows_ingested']} new rows" if summary.get("new_rows_ingested") is not None else "")
              + (f": {summary['error']}" if summary.get("error") else ""))
        summaries.append(summary)
    return summaries


def run_agent_loop():
    from copilot.case_config import case_config
    from copilot.llm import make_llm
    from copilot.prompts import build_system_prompt

    api_key = os.environ.get("OPENAI_API_KEY") or getpass.getpass("Please enter your OpenAI API Key: ")
    llm_with_tools = make_llm(api_key).bind_tools(tools)

    chat_history = [SystemMessage(content=build_system_prompt(case_config))]
    MAX_STEPS = 15

    print("=" * 60)
    print("  DFIR Copilot v2 — Database-Backed Analysis")
    print("  Case database: case_data/case.db")
    print(f"  Scope file: {case_config.path} {'(Loaded)' if case_config.data else '(Not Found/Empty)'}")
    print(f"  Evidence client: {case_config.client_id or '(not set)'}")
    print("  Type 'exit' to quit, 'report' for findings summary")
    print("=" * 60)

    if case_config.client_id_error:
        print(f"\n[!] {case_config.client_id_error}")

    # Prompt user for auto-collection
    elif input("\nDo you want to run the initial auto-collection based on case.yaml? (y/n) [y]: ").lower() in ['', 'y', 'yes']:
        print("\n[*] Starting automatic collection...")
        summaries = auto_collect(case_config)
        auto_prompt = (
            "The initial collection has been run for you. Results per artifact:\n"
            f"{json.dumps(summaries, indent=2)}\n"
            "Follow up on any collection that is still RUNNING with check_collection. "
            "If IOCs are defined in the case, search for them. "
            "If an incident time window is defined, query the timeline for that window."
        )
        chat_history.append(HumanMessage(content=auto_prompt))
        _process_turn(llm_with_tools, chat_history, MAX_STEPS)

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
            print(f"  Total Events: {stats['total_events']}")
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
        _process_turn(llm_with_tools, chat_history, MAX_STEPS)


def _process_turn(llm_with_tools, chat_history, max_steps):
    """Processes a single conversational turn with tool calling loop."""
    try:
        step_count = 0
        while step_count < max_steps:
            step_count += 1
            trim_chat_history(chat_history)

            response = llm_with_tools.invoke(chat_history)
            chat_history.append(response)

            if not response.tool_calls:
                print("\n### Agent Response ###\n")
                if isinstance(response.content, list):
                    for block in response.content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            print(block["text"])
                        elif isinstance(block, str):
                            print(block)
                else:
                    print(response.content)
                break

            for tool_call in response.tool_calls:
                print(f"[*] Agent is running tool: {tool_call['name']}...")
                try:
                    tool_fn = tool_map[tool_call["name"]]
                    tool_output = tool_fn.invoke(tool_call["args"])
                except Exception as e:
                    tool_output = f"Tool execution failed: {e}"

                chat_history.append(ToolMessage(
                    content=str(tool_output),
                    tool_call_id=tool_call["id"],
                    name=tool_call["name"]
                ))

        if step_count >= max_steps:
            print("\n[!] Agent reached maximum tool steps. Halting.")

    except Exception as e:
        print(f"Agent Error: {e}")
