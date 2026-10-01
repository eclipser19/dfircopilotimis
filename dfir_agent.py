import os
import json
import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage

# --- 1. Persistent gRPC Connection Helper ---
CONFIG = pyvelociraptor.LoadConfigFile("api_client.yaml")
CREDS = grpc.ssl_channel_credentials(
    root_certificates=CONFIG["ca_certificate"].encode("utf8"),
    private_key=CONFIG["client_private_key"].encode("utf8"),
    certificate_chain=CONFIG["client_cert"].encode("utf8")
)
CHANNEL = grpc.secure_channel(
    CONFIG["api_connection_string"], 
    CREDS, 
    (('grpc.ssl_target_name_override', "VelociraptorServer"),)
)
STUB = api_pb2_grpc.APIStub(CHANNEL)

def run_vql(query: str, env: dict = None) -> list:
    """Executes a VQL query using the persistent gRPC channel."""
    request = api_pb2.VQLCollectorArgs(
        env=env or [],
        Query=[api_pb2.VQLRequest(Name="AgentQuery", VQL=query)]
    )
    
    results = []
    try:
        for response in STUB.Query(request):
            if response.Response:
                results.extend(json.loads(response.Response))
    except Exception as e:
        return [{"error": str(e)}]
    return results

def safe_json_truncate(res_list: list, max_records: int = 50) -> str:
    """
    Truncates the Python list BEFORE converting to JSON to prevent 
    unclosed JSON strings from breaking the LLM's parsers.
    """
    if not isinstance(res_list, list):
        return str(res_list)
        
    truncated = res_list[:max_records]
    output = json.dumps(truncated, indent=2)
    
    if len(res_list) > max_records:
        output += f"\n\n... [System Note: Truncated {len(res_list) - max_records} additional records to save context window.]"
    
    return output

# --- 2. Define Agent Tools for Mounted Images ---
@tool
def analyze_mounted_image(artifact_name: str, parameters: dict = None) -> str:
    """
    Executes a Velociraptor artifact against the offline forensic image mounted on the server.
    
    Args:
        artifact_name: The name of the artifact (e.g., 'Windows.EventLogs.EvtxHunter').
        parameters: A dictionary of arguments. You MUST include pathing parameters 
                   (like TargetDrive='E:' or EvtxGlob='/mnt/evidence/**/*.evtx') 
                   so the artifact looks at the mounted drive, not the live server.
    """
    args_str = ", ".join([f"{k}='{v}'" for k, v in (parameters or {}).items()])
    if args_str:
        query = f"SELECT * FROM Artifact.{artifact_name}({args_str}) LIMIT 100"
    else:
        query = f"SELECT * FROM Artifact.{artifact_name}() LIMIT 100"
    
    res = run_vql(query)
    return safe_json_truncate(res)

@tool
def raw_vql_query(vql: str) -> str:
    """
    Executes arbitrary Raw VQL on the server. Use this for custom glob() searches 
    against the mounted directory, parsing specific files, or joining data.
    """
    res = run_vql(vql)
    return safe_json_truncate(res)

tools = [analyze_mounted_image, raw_vql_query]
tool_map = {tool.name: tool for tool in tools}

# --- 3. Memory Optimization ---
def trim_chat_history(chat_history: list, keep_last_turns: int = 2) -> list:
    """
    Prunes older ToolMessage outputs to save context window memory.
    A 'turn' is typically Human -> AI -> Tool -> AI.
    """
    ai_message_count = sum(1 for m in chat_history if isinstance(m, AIMessage))
    
    if ai_message_count <= keep_last_turns:
        return chat_history
        
    turns_seen = 0
    # Iterate backwards through history
    for i in range(len(chat_history) - 1, -1, -1):
        msg = chat_history[i]
        if isinstance(msg, AIMessage):
            turns_seen += 1
        
        # If we are older than our kept turns and hit a large ToolMessage, prune it
        if turns_seen > keep_last_turns and isinstance(msg, ToolMessage):
            if msg.content != "[Truncated to save memory]":
                chat_history[i] = ToolMessage(
                    content="[Truncated to save memory]",
                    tool_call_id=msg.tool_call_id,
                    name=msg.name
                )
    return chat_history

# --- 4. Build the Agent ---
def main():
    print("Welcome to the DFIR Copilot (Dead Disk / Mounted Image Mode).")
    
    if "OPENAI_API_KEY" not in os.environ:
        api_key = input("Please enter your OpenAI API Key: ")
        os.environ["OPENAI_API_KEY"] = api_key

    llm = ChatOpenAI(
        model="gpt-5.6-luna", 
        temperature=0,
        base_url="https://tag-news-resource.services.ai.azure.com/openai/v1"
    )
    llm_with_tools = llm.bind_tools(tools)

    # Set to C:\ to test the "mounted disk" queries against your live local machine
    MOUNT_PATH = "C:\\" 

    system_prompt = SystemMessage(content=f'''
    You are an expert Digital Forensics and Incident Response (DFIR) Copilot.
    You are assisting an investigator using Velociraptor. 

    CRITICAL CONTEXT: You are analyzing a DEAD DISK / OFFLINE IMAGE that has been mounted to the server filesystem at: {MOUNT_PATH}
    You are NOT querying live endpoints. Do not attempt to search for client IDs.

    TOOL USAGE RULES:
    1. When using `analyze_mounted_image`, you MUST pass parameters that redirect the artifact to the mount path. For example, if running a Windows artifact, pass `TargetDrive='{MOUNT_PATH}'` or modify glob parameters to point to `{MOUNT_PATH}`. 
    2. If an artifact defaults to querying `C:/`, it will scan the live server by mistake unless you override its target path parameters.
    3. When using `raw_vql_query`, use the `glob()` plugin and prepend `{MOUNT_PATH}` to all paths. Example: 
       `SELECT * FROM parse_evtx(filename=glob(globs='{MOUNT_PATH}/Windows/System32/winevt/Logs/Security.evtx'))`
    4. Always analyze the returned JSON data and summarize your findings clearly. If the JSON is truncated, state that you are analyzing a sample.
    ''')

    chat_history = [system_prompt]

    while True:
        user_input = input("\nInvestigator> ")
        if user_input.lower() in ['quit', 'exit']:
            break
        
        chat_history.append(HumanMessage(content=user_input))
        
        try:
            while True:
                # Truncate old tool data before hitting the LLM API limit
                chat_history = trim_chat_history(chat_history)
                
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
                    tool_fn = tool_map[tool_call["name"]]
                    tool_output = tool_fn.invoke(tool_call["args"])
                    
                    chat_history.append(ToolMessage(
                        content=str(tool_output),
                        tool_call_id=tool_call["id"],
                        name=tool_call["name"]
                    ))
                    
        except Exception as e:
            print(f"Agent Error: {e}")

if __name__ == "__main__":
    main()
