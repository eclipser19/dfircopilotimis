import os
from langchain_openai import ChatOpenAI
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

def run_agent_loop():
    if "OPENAI_API_KEY" not in os.environ:
        os.environ["OPENAI_API_KEY"] = input("Please enter your OpenAI API Key: ")

    llm = ChatOpenAI(
        model="gpt-5.6-luna",
        temperature=0,
        base_url="https://tag-news-resource.services.ai.azure.com/openai/v1"
    )
    llm_with_tools = llm.bind_tools(tools)

    from copilot.case_config import case_config
    
    # Prepend the case.yaml context to the system prompt
    case_context = case_config.build_system_context()
    
    system_prompt = SystemMessage(content=f'''You are an expert DFIR (Digital Forensics and Incident Response) Copilot.
You interface with a Velociraptor server and a local case database.

{case_context}

## YOUR WORKFLOW

**Step 1 — Collect:** Use `search_clients` to find the target client (look for "Virtual Host" for dead-disk analysis). 
Then use `collect_artifact` to run Velociraptor artifacts on it. Results are automatically stored in the case database.

**Step 2 — Analyze:** Use `query_timeline`, `search_iocs`, and `pivot_entity` to query the database. 
These tools let you correlate across ALL collected artifacts, filter by time windows, and trace entities.
Use `get_event_detail` to inspect specific events in full.
Use `case_summary` to see what data has been collected so far.

**Step 3 — Record:** When you discover something suspicious, use `record_finding` to log it with evidence IDs, 
confidence level, and MITRE ATT&CK technique. Findings are saved permanently for the final report.

## KEY ARTIFACTS TO KNOW
- `Windows.EventLogs.EvtxHunter` — Search Windows event logs (params: EvtxGlob, SearchRegex, etc.)
- `Windows.Timeline.Prefetch` — Prefetch execution history
- `Windows.System.Amcache.InventoryApplicationFile` — Amcache execution evidence
- `Windows.System.Powershell.PSReadline` — PowerShell command history
- `Windows.Forensics.NTFS.MFT` — MFT filesystem timeline
- `Windows.Network.Netstat` — Active network connections
- `Windows.Persistence.PermanentWMIEvents` — WMI persistence
- `Windows.System.TaskScheduler` — Scheduled tasks
- `Generic.Client.Info` — Basic system info
Use `server_vql_query` with `SELECT name FROM artifact_definitions() WHERE name =~ 'keyword'` to discover more artifacts.

## RULES
1. ALWAYS collect artifacts before trying to query the timeline. The database starts empty.
2. When the investigator gives a timeframe, collect relevant artifacts first, then use `query_timeline` to filter.
3. When correlating, collect MULTIPLE artifacts, then use `search_iocs` or `pivot_entity` to cross-reference.
4. Keep your analysis structured: state what you collected, what you found, and what it means.
5. Use `record_finding` for anything suspicious — these become the report.
''')

    chat_history = [system_prompt]
    MAX_STEPS = 15

    print("=" * 60)
    print("  DFIR Copilot v2 — Database-Backed Analysis")
    print("  Case database: case_data/case.db")
    print(f"  Scope file: {case_config.path} {'(Loaded)' if case_config.data else '(Not Found/Empty)'}")
    print("  Type 'exit' to quit, 'report' for findings summary")
    print("=" * 60)
    
    # Prompt user for auto-collection
    if input("\nDo you want to run the initial auto-collection based on case.yaml? (y/n) [y]: ").lower() in ['', 'y', 'yes']:
        print("\n[*] Starting automatic background collection...")
        auto_prompt = (
            f"Please begin the investigation by collecting the following artifacts on the virtual dead-disk client: "
            f"{', '.join(case_config.artifacts_to_collect)}. "
            f"If IOCs are defined in the case, run a search for them after collection. "
            f"If an incident time window is defined, query the timeline for that window."
        )
        chat_history.append(HumanMessage(content=auto_prompt))
        
        # We process this first message immediately
        # (Using a helper function to avoid duplicating the while True loop)
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
                print(f"\n  [{f['confidence'].upper()}] {f['title']}")
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
