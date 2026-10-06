import json
import os

import streamlit as st
from langchain_core.messages import HumanMessage, SystemMessage

from copilot import cases, collection, commands, outputs, tools as copilot_tools
from copilot.agent import TokenUsage, run_turn, status_line
from copilot.case_config import case_config
from copilot.database import case_db
from copilot.llm import make_llm
from copilot.prompts import build_system_prompt
from copilot.tools import tools

st.set_page_config(page_title="DFIR Copilot", page_icon="🕵️", layout="wide")

MAX_DOWNLOAD_MB = 50  # larger files are listed with their path instead of loaded into the page
MIME = {"html": "text/html", "md": "text/markdown", "csv": "text/csv", "json": "application/json",
        "zip": "application/zip"}

# ==========================================
# Session state
# ==========================================
if "chat_history" not in st.session_state:
    st.session_state.chat_history = [SystemMessage(content=build_system_prompt(case_config))]
    st.session_state.messages = []      # [{role, content, log: [str], files: [output rows]}]
    st.session_state.usage = TokenUsage()
    st.session_state.pending = []       # agent collection requests awaiting approval
    st.session_state.next_request = 1
    st.session_state.triage_dismissed = False


def queue_request(artifact: str, params: dict):
    """Agent collection requests wait for the investigator's Approve/Deny in the sidebar."""
    st.session_state.pending.append({"id": st.session_state.next_request, "artifact": artifact, "params": params})
    st.session_state.next_request += 1
    return "queued"


def restart_conversation(note: str):
    """After a case switch: new system prompt for the new case, fresh agent context."""
    st.session_state.chat_history = [SystemMessage(content=build_system_prompt(case_config))]
    st.session_state.pending = []
    st.session_state.triage_dismissed = False
    st.session_state.messages.append({"role": "assistant", "content": note})


def after_possible_switch():
    if cases.consume_switch():
        restart_conversation(f"📁 **Now in case `{cases.current_id()}` — {case_config.case_name}.** "
                             f"Fresh conversation; earlier messages belong to the previous case.")
        st.rerun()


# This app is meant for one investigator at a time: the approval hook and the active case are process-wide.
collection.CONFIRM = queue_request


# ==========================================
# Rendering helpers
# ==========================================
def download_button(entry: dict, key: str):
    path = entry["path"]
    name = os.path.basename(path)
    if not os.path.exists(path):
        st.caption(f"📄 {name} — no longer on disk ({path})")
        return
    size_mb = os.path.getsize(path) / (1024 * 1024)
    if size_mb > MAX_DOWNLOAD_MB:
        st.caption(f"📦 {name} ({size_mb:.0f} MB) — too large to download here; on the server at `{path}`")
        return
    with open(path, "rb") as f:
        st.download_button(f"⬇️ {name} — {entry['description']}", data=f.read(), file_name=name,
                           mime=MIME.get(name.rsplit(".", 1)[-1], "application/octet-stream"), key=key)


def render_message(msg: dict, index: int):
    with st.chat_message(msg["role"]):
        if msg.get("log"):
            with st.expander("Steps", expanded=False):
                st.text("\n".join(msg["log"]))
        if msg.get("content"):
            st.markdown(msg["content"])
        for entry in msg.get("files", []):
            download_button(entry, key=f"dl-{index}-{entry['output_id']}")


def agent_turn(text: str, show_user: bool = True):
    """Runs one agent turn; new files the agent produced are attached to its message."""
    if "llm_with_tools" not in st.session_state:
        st.error("Enter the API key in the sidebar first.")
        return
    if show_user:
        st.session_state.messages.append({"role": "user", "content": text})
        with st.chat_message("user"):
            st.markdown(text)
    st.session_state.chat_history.append(HumanMessage(content=text))
    before = outputs.last_output_id()
    log, notices = [], []

    with st.chat_message("assistant"):
        status = st.status("Investigating...", expanded=True)

        def emit(kind, payload):
            if kind == "tool":
                log.append(f"⚙️ {payload}")
                status.write(f"⚙️ `{payload}`")
            elif kind == "collection":
                log.append(f"   {payload}")
                status.text(payload)
            elif kind == "notice":
                notices.append(payload)
                status.warning(payload)
            elif kind == "usage":
                log.append(payload)

        answer = run_turn(st.session_state.llm_with_tools, st.session_state.chat_history, case_config.max_steps,
                          st.session_state.usage, case_config.max_tokens_per_turn,
                          st.session_state.finalizer, emit)
        status.update(label="Done", state="complete", expanded=False)
        content = answer or "\n\n".join(f"⚠️ {n}" for n in notices) or "No answer."
        files = outputs.produced_since(before)
        st.markdown(content)
        for entry in files:
            download_button(entry, key=f"dl-new-{entry['output_id']}")
        st.caption(st.session_state.usage.summary())
    st.session_state.messages.append({"role": "assistant", "content": content, "log": log, "files": files})


def run_triage(analyze: bool):
    """The case's triage collections (no LLM), then optionally an agent analysis turn."""
    lines, summaries = [], []
    with st.chat_message("assistant"):
        status = st.status("Running triage collection...", expanded=True)
        for step in case_config.collection_plan:
            artifact, params = step["artifact"], step["parameters"]
            status.write(f"Collecting `{artifact}`...")
            try:
                summary = collection.collect(artifact, params)
            except collection.CollectionError as e:
                summary = {"artifact": artifact, "state": "NOT_STARTED", "error": str(e)}
            summaries.append(summary)
            lines.append(status_line(summary))
            status.text(lines[-1])
        status.update(label="Triage collection finished", state="complete", expanded=False)
    content = "**Triage collection**\n\n```\n" + "\n".join(lines) + "\n```"
    st.session_state.messages.append({"role": "assistant", "content": content})

    started = [s for s in summaries if s.get("state") != "NOT_STARTED"]
    if not (analyze and started):
        st.rerun()  # refresh sidebar stats
    agent_turn(
        "The initial collection has been run for you. Results per artifact:\n"
        f"{json.dumps(summaries, indent=2)}\n"
        "Follow up on any collection that is still RUNNING with check_collection. "
        "If IOCs are defined in the case, search for them. "
        "If an incident time window is defined, query the timeline for that window.",
        show_user=False)


def resolve_request(request: dict, approved: bool):
    st.session_state.pending = [r for r in st.session_state.pending if r["id"] != request["id"]]
    if not approved:
        note = f"[Investigator] Declined the requested collection of {request['artifact']}."
        st.session_state.chat_history.append(HumanMessage(content=note))
        st.session_state.messages.append({"role": "assistant", "content": f"❌ Declined `{request['artifact']}`."})
        return
    with st.chat_message("assistant"):
        with st.spinner(f"Collecting {request['artifact']}..."):
            try:
                summary = collection.collect(request["artifact"], request["params"])
            except collection.CollectionError as e:
                summary = {"artifact": request["artifact"], "state": "NOT_STARTED", "error": str(e)}
    st.session_state.chat_history.append(HumanMessage(
        content=f"[Investigator] Approved and ran the requested collection. Result: {json.dumps(summary)}"))
    st.session_state.messages.append({
        "role": "assistant",
        "content": f"✅ Approved `{request['artifact']}`\n\n```\n{status_line(summary)}\n```\n\n"
                   f"Ask the copilot to continue when ready."})


# ==========================================
# Sidebar
# ==========================================
action = None
with st.sidebar:
    st.title("🕵️ DFIR Copilot")

    api_key_input = st.text_input("Azure OpenAI API Key", type="password",
                                  value=os.environ.get("OPENAI_API_KEY", ""))
    if api_key_input and ("llm_with_tools" not in st.session_state
                          or st.session_state.get("current_api_key") != api_key_input):
        # Kept in this browser session only; never written to os.environ.
        st.session_state.current_api_key = api_key_input
        llm = make_llm(api_key_input)
        st.session_state.llm_with_tools = llm.bind_tools(tools)
        st.session_state.finalizer = llm.bind_tools(tools, tool_choice="none")

    st.divider()
    st.subheader("📁 Case")
    case_rows = cases.list_cases()
    current = cases.current_id()
    names = {c["id"]: c["name"] for c in case_rows}
    ids = list(names) if current in names else [current] + list(names)
    picked = st.selectbox("Active case", ids, index=ids.index(current),
                          format_func=lambda i: f"{i} — {names.get(i, case_config.case_name)}")
    if picked != current:
        cases.switch(picked)
        after_possible_switch()
    with st.expander("➕ New case", expanded=False):
        with st.form("new_case", clear_on_submit=True):
            new_id = st.text_input("Case ID (folder name)", placeholder="acme-ws42")
            new_name = st.text_input("Name", placeholder="ACME workstation 42")
            new_client = st.text_input("Velociraptor client ID", placeholder="C.1234abcd...")
            c1, c2 = st.columns(2)
            new_start = c1.text_input("Window start (UTC)", placeholder="2024-01-15T00:00:00Z")
            new_end = c2.text_input("Window end (UTC)", placeholder="2024-01-17T00:00:00Z")
            new_offset = st.number_input("Host clock ahead of UTC (minutes)", value=0, step=15)
            new_desc = st.text_area("What happened / what to find out")
            if st.form_submit_button("Create and open"):
                try:
                    cases.create(new_id.strip(), new_name.strip(), new_client.strip(), new_start.strip(),
                                 new_end.strip(), new_desc.strip(), int(new_offset))
                    cases.switch(new_id.strip())
                    after_possible_switch()
                except cases.CaseError as e:
                    st.error(str(e))
    st.text(f"{case_config.case_name}\nAnalyst: {case_config.analyst}")
    if case_config.client_id_error:
        st.warning(case_config.client_id_error)
    else:
        st.text(f"Evidence client: {case_config.client_id}")
    if case_config.has_scope:
        st.text(f"Window: {case_config.start_time}\n     to {case_config.end_time}")
    if case_config.clock_offset_minutes:
        st.caption(f"Host clock offset: {case_config.clock_offset_minutes:+d} min")
    st.caption(f"LLM tokens this session: "
               f"{st.session_state.usage.session_input + st.session_state.usage.session_output:,}")

    with st.expander("🧰 Triage collection", expanded=False):
        for step in case_config.collection_plan:
            st.caption(f"- {step['artifact']}" + (f" {json.dumps(step['parameters'])}" if step["parameters"] else ""))
        analyze = st.checkbox("Analyze with the agent afterwards", value=True, key="triage_analyze")
        if st.button("Run triage collection", disabled=bool(case_config.client_id_error)):
            action = ("triage", analyze)

    if st.session_state.pending:
        st.subheader("⏳ Collection requests")
        for req in st.session_state.pending:
            st.markdown(f"**{req['artifact']}**")
            if req["params"]:
                st.code(json.dumps(req["params"], indent=1), language="json")
            c1, c2 = st.columns(2)
            if c1.button("Approve", key=f"approve-{req['id']}"):
                action = ("approve", req)
            if c2.button("Deny", key=f"deny-{req['id']}"):
                action = ("deny", req)

    st.subheader("📊 Database")
    stats = case_db.get_stats()
    st.metric("Records", stats["total_records"])
    st.caption(f"{stats['timeline_events']} timeline events · {stats['undated_records']} without timestamps")
    for src in stats["by_source"]:
        st.caption(f"- {src['source']} ({src['records']})")

    st.subheader("🚩 Findings")
    active = case_db.get_findings()
    for f in active:
        st.caption(f"[{(f['confidence'] or 'unknown').upper()}] {f['title']}")
    if active:
        with st.expander("Retract a finding", expanded=False):
            labels = {f"{f['title']} ({f['finding_id']})": f["finding_id"] for f in active}
            choice = st.selectbox("Finding", list(labels), key="retract_choice")
            reason = st.text_input("Reason (e.g. the contradicting evidence)", key="retract_reason")
            if st.button("Retract", disabled=not reason.strip()):
                case_db.retract_finding(labels[choice], reason.strip())
                st.session_state.chat_history.append(HumanMessage(
                    content=f"[Investigator] Retracted finding '{choice}': {reason.strip()}"))
                st.rerun()

    st.subheader("📄 Report")
    chosen = st.multiselect("Report formats", ["html", "md"], default=case_config.report_formats,
                            key="report_formats", help="Formats cost no extra LLM tokens.")
    copilot_tools.REPORT_FORMATS = chosen or None

    files = outputs.produced_since(0)
    if files:
        st.subheader("📄 Files")
        st.caption(f"Saved in `{outputs.output_dir()}`")
        for entry in reversed(files[-15:]):
            download_button(entry, key=f"dl-side-{entry['output_id']}")

# ==========================================
# Main area
# ==========================================
st.title("Interactive Investigation")
st.caption(f"Case `{cases.current_id()}` — {case_config.case_name} · type `/help` for free commands")
hint = cases.legacy_data_hint()
if hint:
    st.warning(hint)

for i, msg in enumerate(st.session_state.messages):
    render_message(msg, i)

# First visit to an empty case: offer the triage collection (the CLI asks the same question).
if (not case_db.get_collections() and not st.session_state.triage_dismissed and action is None
        and not case_config.client_id_error):
    with st.container(border=True):
        st.markdown("**No data collected for this case yet.** Run the initial triage collection from "
                    f"`{case_config.path}`? It needs no LLM; the agent can analyze the results afterwards.")
        c1, c2 = st.columns([1, 4])
        if c1.button("Run triage", type="primary"):
            action = ("triage", st.session_state.get("triage_analyze", True))
        if c2.button("Skip"):
            st.session_state.triage_dismissed = True
            st.rerun()

if action:
    kind, arg = action
    if kind == "triage":
        st.session_state.triage_dismissed = True
        run_triage(analyze=arg)
    elif kind in ("approve", "deny"):
        resolve_request(arg, approved=(kind == "approve"))
        st.rerun()

if prompt := st.chat_input("Ask the copilot to investigate... (/help for commands)"):
    reply = commands.handle(prompt)
    if reply is not None:
        st.session_state.messages.append({"role": "user", "content": prompt})
        st.session_state.messages.append({"role": "assistant", "content": reply})
        after_possible_switch()
        st.rerun()
    agent_turn(prompt)
    after_possible_switch()
    if st.session_state.pending:
        st.rerun()  # show the new approval requests in the sidebar
