import streamlit as st
import os
import json
import sqlite3
import pandas as pd
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage

# Copilot imports
from copilot.tools import tools, tool_map
from copilot.case_config import case_config
from copilot.database import case_db
from copilot.agent import trim_chat_history

st.set_page_config(page_title="DFIR Copilot", page_icon="🕵️", layout="wide")

# ==========================================
# Initialize Agent Session State
# ==========================================
if "chat_history" not in st.session_state:
    case_context = case_config.build_system_context()
    sys_msg = SystemMessage(content=f'''You are an expert DFIR (Digital Forensics and Incident Response) Copilot.
You interface with a Velociraptor server and a local case database.

{case_context}

## YOUR WORKFLOW
**Step 1 — Collect:** Use `search_clients` to find the target client (look for "Virtual Host"). 
Then use `collect_artifact` to run Velociraptor artifacts on it.
**Step 2 — Analyze:** Use `query_timeline`, `search_iocs`, and `pivot_entity` to query the database.
**Step 3 — Record:** Use `record_finding` to log anything suspicious. At the end, use `generate_report`.
''')
    st.session_state.chat_history = [sys_msg]
    st.session_state.messages = []  # For UI display

# ==========================================
# UI Layout: Sidebar (Case Info & DB)
# ==========================================
with st.sidebar:
    st.title("🕵️ DFIR Copilot")
    st.write("v2.0 — Velociraptor + Case DB")
    
    # API Key Input
    api_key_input = st.text_input("Azure OpenAI API Key", type="password", value=os.environ.get("OPENAI_API_KEY", ""))
    
    # Initialize or update LLM if API key is provided
    if api_key_input and ("llm_with_tools" not in st.session_state or st.session_state.get("current_api_key") != api_key_input):
        st.session_state.current_api_key = api_key_input
        os.environ["OPENAI_API_KEY"] = api_key_input
        st.session_state.llm = ChatOpenAI(
            model="gpt-5.6-luna",
            temperature=0,
            api_key=api_key_input,
            base_url="https://tag-news-resource.services.ai.azure.com/openai/v1"
        )
        st.session_state.llm_with_tools = st.session_state.llm.bind_tools(tools)
    
    st.divider()
    
    st.subheader("📁 Case Scope")
    st.text(f"Name: {case_config.case_name}")
    st.text(f"Analyst: {case_config.analyst}")
    if case_config.has_scope:
        st.text(f"Time: {case_config.start_time}\n   to {case_config.end_time}")
    else:
        st.text("Time: No scope defined.")
        
    st.subheader("📊 Database Stats")
    if st.button("Refresh Stats"):
        pass # Streamlit auto-reruns anyway
    
    stats = case_db.get_stats()
    st.metric("Total Events", stats["total_events"])
    
    if stats["by_source"]:
        st.write("**Collected Artifacts:**")
        for src in stats["by_source"]:
            st.caption(f"- {src['source']} ({src['count']})")
    else:
        st.caption("No data collected yet.")
        
    st.subheader("🚩 Findings")
    findings = case_db.get_findings()
    st.metric("Recorded Findings", len(findings))
    for f in findings:
        st.caption(f"[{f['confidence'].upper()}] {f['title']}")

# ==========================================
# UI Layout: Main Chat Interface
# ==========================================
st.title("Interactive Investigation")

# Render existing chat
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# User Input
if prompt := st.chat_input("Ask the copilot to investigate..."):
    # Display user prompt
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Agent execution
    if "llm_with_tools" not in st.session_state:
        with st.chat_message("assistant"):
            st.error("Please enter your Azure OpenAI API Key in the sidebar first.")
    else:
        st.session_state.chat_history.append(HumanMessage(content=prompt))
        
        with st.chat_message("assistant"):
            status_container = st.empty()
            
            step_count = 0
            MAX_STEPS = 15
            final_answer = ""
            
            while step_count < MAX_STEPS:
                step_count += 1
                trim_chat_history(st.session_state.chat_history)
                
                with status_container.status(f"Thinking (Step {step_count})...", expanded=True) as status:
                    response = st.session_state.llm_with_tools.invoke(st.session_state.chat_history)
                    st.session_state.chat_history.append(response)

                    if not response.tool_calls:
                        final_answer = response.content
                        status.update(label="Response ready", state="complete", expanded=False)
                        break

                    for tool_call in response.tool_calls:
                        st.write(f"⚙️ Running tool: `{tool_call['name']}`")
                        try:
                            tool_fn = tool_map[tool_call["name"]]
                            tool_output = tool_fn.invoke(tool_call["args"])
                        except Exception as e:
                            tool_output = f"Tool execution failed: {e}"
                            
                        st.session_state.chat_history.append(ToolMessage(
                            content=str(tool_output),
                            tool_call_id=tool_call["id"],
                            name=tool_call["name"]
                        ))

            if final_answer:
                if isinstance(final_answer, list):
                    # Handle structured blocks
                    text_out = "\n".join([b["text"] for b in final_answer if isinstance(b, dict) and b.get("type") == "text"])
                    st.markdown(text_out)
                    st.session_state.messages.append({"role": "assistant", "content": text_out})
                else:
                    st.markdown(final_answer)
                    st.session_state.messages.append({"role": "assistant", "content": final_answer})
            else:
                st.error("Agent reached maximum steps without a final answer.")
