import json
import os
import re

import streamlit as st
from langchain_core.messages import HumanMessage, SystemMessage

from copilot import approvals, auth, cases, collection, commands, conversation, outputs, tools as copilot_tools
from copilot import llm as llm_config
from copilot.agent import TokenUsage, run_turn, status_line
from copilot.case_config import case_config
from copilot.database import case_db
from copilot.prompts import build_system_prompt
from copilot.tools import tools

st.set_page_config(page_title="DFIR Copilot", page_icon="🕵️", layout="wide")


# ==========================================
# Login (local accounts, works offline; see copilot/auth.py)
# ==========================================
def login_gate():
    """Stops the page here until a configured user signs in. Without accounts the app runs open."""
    user = st.session_state.get("user")
    if user and auth.is_user(user):
        return
    if user:                                   # account removed on the server: sign out
        st.session_state.clear()
    if not auth.login_required():
        return
    st.title("🕵️ DFIR Copilot")
    if not auth.configured():
        st.error("Sign-in is required (DFIR_REQUIRE_LOGIN) but no accounts exist yet. On the server, run "
                 "`python -m copilot.auth add <username>`.")
        st.stop()
    with st.form("login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in", type="primary")
    if submitted:
        username = username.strip()
        if auth.verify(username, password):
            st.session_state.user = username
            st.rerun()
        wait = auth.locked_for(username)
        st.error(f"Too many failed attempts for this account. Try again in {wait // 60 + 1} min."
                 if wait else "Wrong username or password.")
    st.stop()


login_gate()

MAX_DOWNLOAD_MB = 50  # larger files are listed with their path instead of loaded into the page
MIME = {"html": "text/html", "md": "text/markdown", "csv": "text/csv", "json": "application/json",
        "zip": "application/zip"}

# ==========================================
# Session state
# ==========================================
if "usage" not in st.session_state:
    st.session_state.usage = TokenUsage()
    st.session_state.pending = []       # agent requests awaiting approval (each tied to its case)
    st.session_state.next_request = 1
    st.session_state.triage_dismissed = False


def open_case_chat(note: str = ""):
    """Shows the active case's saved conversation (or a new one) and gives the agent its memory back."""
    case_id = cases.current_id()
    messages, history = conversation.load(case_id, build_system_prompt(case_config))
    st.session_state.case_id = case_id
    st.session_state.messages = messages      # [{role, content, log: [str], files: [output rows]}]
    st.session_state.chat_history = history
    st.session_state.triage_dismissed = False
    if note:
        st.session_state.messages.append({"role": "assistant", "content": note})


def persist():
    """Saves this session's conversation to the case it belongs to."""
    if "case_id" in st.session_state:
        conversation.save(st.session_state.case_id, st.session_state.messages, st.session_state.chat_history)


# Every run: save the conversation to its own case, then follow the active case if it changed
# (sidebar, /case, the agent, the New case form, or another tab).
if "case_id" not in st.session_state:
    open_case_chat()
else:
    persist()
    if st.session_state.case_id != cases.current_id():
        previous = st.session_state.case_id
        restored = bool(conversation.load(cases.current_id(), "")[0])
        open_case_chat((f"📁 **Back in case `{cases.current_id()}` — {case_config.case_name}.** Conversation restored."
                        if restored else
                        f"📁 **Now in case `{cases.current_id()}` — {case_config.case_name}.** New conversation.")
                       + f" (`{previous}` was saved.)" + st.session_state.pop("case_note", ""))
cases.consume_switch()


def queue_request(request: dict):
    """Agent requests wait for the investigator's Approve/Deny in the sidebar (per case)."""
    request["id"] = st.session_state.next_request
    st.session_state.next_request += 1
    st.session_state.pending.append(request)
    return "queued"


def pending_here() -> list:
    return [r for r in st.session_state.pending if r.get("case_id") == cases.current_id()]


def after_possible_switch():
    """Rerun when the active case or its settings changed (the top of the script does the rest)."""
    if cases.consume_settings_change():
        st.session_state.chat_history[0] = SystemMessage(content=build_system_prompt(case_config))
    if cases.consume_switch() or st.session_state.case_id != cases.current_id():
        st.rerun()


IOC_LABELS = {"ips": "IP addresses", "domains": "Domains", "hashes": "Hashes", "filenames": "File names",
              "users": "Accounts"}


def ioc_fields(prefix: str, initial: dict = None):
    """IOC text areas (one value per line) with free and AI extraction from the description."""
    st.markdown("**IOCs** (one per line)")
    c1, c2 = st.columns(2)
    c1.button("Extract from description", key=prefix + "extract", on_click=extract_iocs_cb, args=(prefix, False),
              help="Pattern based, free: IPs, domains, hashes, file names, accounts (also defanged).")
    c2.button("✨ AI extract", key=prefix + "ai_extract", on_click=extract_iocs_cb, args=(prefix, True),
              disabled="llm" not in st.session_state,
              help="One small LLM call; catches what patterns miss. Values are checked against the text.")
    for kind, label in IOC_LABELS.items():
        st.text_area(label, value="\n".join((initial or {}).get(kind, [])), key=f"{prefix}ioc_{kind}", height=68)


def _ioc_values(prefix: str) -> dict:
    return {k: [v.strip() for v in st.session_state.get(f"{prefix}ioc_{k}", "").splitlines() if v.strip()]
            for k in IOC_LABELS}


def extract_iocs_cb(prefix: str, use_llm: bool):
    from copilot.iocs import extract_iocs, llm_extract_iocs, merge
    text = st.session_state.get(prefix + "desc", "")
    found = extract_iocs(text)
    if use_llm and "llm" in st.session_state:
        try:
            found = merge(found, llm_extract_iocs(st.session_state.llm, text))
        except Exception as e:  # network/API errors: keep the free result
            st.session_state.cs_message = f"AI extraction failed: {e}"
    combined = merge(_ioc_values(prefix), found)
    for kind in IOC_LABELS:
        st.session_state[f"{prefix}ioc_{kind}"] = "\n".join(combined[kind])


def create_case_cb():
    st.session_state.nc_error = ""
    case_id = st.session_state.get("nc_id", "").strip()
    copy_from = st.session_state.get("nc_copy")
    try:
        cases.create(case_id, st.session_state.get("nc_name", "").strip(),
                     st.session_state.get("nc_client", "").strip(), st.session_state.get("nc_start", "").strip(),
                     st.session_state.get("nc_end", "").strip(), st.session_state.get("nc_desc", "").strip(),
                     int(st.session_state.get("nc_offset", 0)), _ioc_values("nc_"),
                     None if copy_from in (None, "(none)") else copy_from)
        cases.switch(case_id)
    except cases.CaseError as e:
        st.session_state.nc_error = str(e)
        return
    for key in [k for k in st.session_state if str(k).startswith("nc_")]:
        del st.session_state[key]
    if copy_from not in (None, "(none)"):
        st.session_state.case_note = f" Collected data copied from `{copy_from}`."


def save_settings_cb(case_id: str):
    p = f"cs_{case_id}_"
    try:
        cases.update(case_id, name=st.session_state[p + "name"], client_id=st.session_state[p + "client"],
                     start_time=st.session_state[p + "start"], end_time=st.session_state[p + "end"],
                     clock_offset_minutes=int(st.session_state[p + "offset"]),
                     description=st.session_state[p + "desc"], iocs=_ioc_values(p))
    except cases.CaseError as e:
        st.session_state.cs_message = f"❌ {e}"
        return
    cases.consume_settings_change()
    st.session_state.chat_history[0] = SystemMessage(content=build_system_prompt(case_config))
    st.session_state.cs_message = "✅ Saved. The agent now works with the new settings."


# This app is meant for one investigator at a time: the approval hook and the active case are process-wide.
approvals.ASK = queue_request


# ==========================================
# Rendering helpers
# ==========================================
def download_button(entry: dict, key: str):
    path = outputs.locate(entry)
    name = os.path.basename(entry["path"].replace("\\", "/"))
    if not path:
        st.caption(f"📄 {name} — not found (last known at {entry['path']}; also looked in "
                   f"{outputs.output_dir()})")
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
        # Links to local paths can't work in a browser; files come as download buttons instead.
        content = re.sub(r"\[([^\]]+)\]\((?!https?://)[^)]*\)", r"\1", content)
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
    """Runs (or declines) a queued agent request and tells the agent what happened."""
    st.session_state.pending = [r for r in st.session_state.pending if r["id"] != request["id"]]
    label = approvals.describe(request)
    if not approved:
        approvals.resolve(request, False, actor=st.session_state.get("user"))
        st.session_state.chat_history.append(HumanMessage(content=f"[Investigator] Declined: {label}."))
        st.session_state.messages.append({"role": "assistant", "content": f"❌ Declined — {label}"})
        return
    with st.chat_message("assistant"):
        with st.spinner(f"{label}..."):
            try:
                result = approvals.resolve(request, True, actor=st.session_state.get("user"))
            except (approvals.ApprovalError, collection.CollectionError, cases.CaseError) as e:
                result = f"Failed: {e}"
    shown = f"```\n{status_line(result)}\n```" if isinstance(result, dict) else str(result)
    st.session_state.chat_history.append(HumanMessage(
        content=f"[Investigator] Approved: {label}. Result: {json.dumps(result, default=str)}"))
    st.session_state.messages.append({"role": "assistant",
                                      "content": f"✅ Approved — {label}\n\n{shown}\n\n"
                                                 f"Ask the copilot to continue when ready."})
    if cases.consume_settings_change():
        st.session_state.chat_history[0] = SystemMessage(content=build_system_prompt(case_config))


# ==========================================
# Sidebar
# ==========================================
action = None
with st.sidebar:
    st.title("🕵️ DFIR Copilot")

    if st.session_state.get("user"):
        c1, c2 = st.columns([3, 2])
        c1.caption(f"👤 Signed in as **{st.session_state.user}**")
        if c2.button("Sign out"):
            persist()
            st.session_state.clear()
            st.rerun()
    else:
        st.warning("No sign-in configured: anyone who can reach this page can use it. "
                   "Add an account with `python -m copilot.auth add <username>`.")

    # A server-side key is used directly and never sent to the browser (a pre-filled password
    # field is readable by every visitor). A local model needs no key at all. Only a cloud
    # endpoint without a server key asks each investigator for theirs.
    user_key = ""
    if llm_config.needs_user_key():
        user_key = st.text_input("API key for the LLM endpoint", type="password")
    elif llm_config.is_local():
        st.caption(f"🖥️ Local model `{llm_config.model_name()}` at {llm_config.base_url()}")
    else:
        st.caption("🔑 Using the server's API key.")
    key_id = user_key or ("" if llm_config.needs_user_key() else "server")
    if key_id and ("llm_with_tools" not in st.session_state or st.session_state.get("current_api_key") != key_id):
        # Kept in this browser session only; never written to os.environ.
        st.session_state.current_api_key = key_id
        llm = llm_config.make_llm(user_key or None)
        st.session_state.llm = llm
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
        st.caption("Fields marked * are required. The client ID can be added later, but is needed to collect.")
        st.text_input("Case ID *", placeholder="acme-ws42", key="nc_id",
                      help="Folder name: letters, digits, - and _")
        st.text_input("Name *", placeholder="ACME workstation 42", key="nc_name")
        st.text_input("Velociraptor client ID", placeholder="C.1234abcd...", key="nc_client")
        c1, c2 = st.columns(2)
        c1.text_input("Window start (UTC)", placeholder="2024-01-15T00:00:00Z", key="nc_start")
        c2.text_input("Window end (UTC)", placeholder="2024-01-17T00:00:00Z", key="nc_end")
        st.number_input("Host clock ahead of UTC (minutes)", value=0, step=15, key="nc_offset")
        st.text_area("What happened / what to find out", key="nc_desc")
        ioc_fields("nc_")
        sources = ["(none)"] + [c["id"] for c in case_rows if c["has_data"]]
        st.selectbox("Copy collected data from", sources, key="nc_copy",
                     help="Only cases on the same evidence client. Findings are not copied.")
        st.button("Create and open", type="primary", on_click=create_case_cb)
        if st.session_state.get("nc_error"):
            st.error(st.session_state.nc_error)

    if cases.current_id() != cases.LEGACY_ID:
        with st.expander("⚙️ Case settings", expanded=False):
            cid = cases.current_id()
            p = f"cs_{cid}_"
            st.text_input("Name *", value=case_config.case_name, key=p + "name")
            st.text_input("Velociraptor client ID", value=case_config.client_id, key=p + "client")
            c1, c2 = st.columns(2)
            c1.text_input("Window start (UTC)", value=case_config.start_time, key=p + "start")
            c2.text_input("Window end (UTC)", value=case_config.end_time, key=p + "end")
            st.number_input("Host clock ahead of UTC (minutes)", value=case_config.clock_offset_minutes,
                            step=15, key=p + "offset")
            st.text_area("Description", value=case_config.description, key=p + "desc")
            ioc_fields(p, case_config.iocs)
            st.button("Save settings", on_click=save_settings_cb, args=(cid,))
            if st.session_state.get("cs_message"):
                st.caption(st.session_state.cs_message)
    if st.button("🧹 New conversation", help="Clears this case's chat and the agent's memory of it. "
                                          "Collected data and findings stay."):
        conversation.clear(cases.current_id())
        open_case_chat()
        st.rerun()
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

    if pending_here():
        st.subheader("⏳ Awaiting your approval")
        st.caption("The agent asked to change something. Nothing happens until you approve.")
        for req in pending_here():
            st.markdown(f"**{approvals.ACTIONS.get(req['kind'], req['kind']).capitalize()}**")
            st.caption(req["summary"])
            if req["kind"] == "collect" and req["details"].get("params"):
                st.code(json.dumps(req["details"]["params"], indent=1), language="json")
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
                who = st.session_state.get("user")
                case_db.retract_finding(labels[choice], reason.strip() + (f" (retracted by {who})" if who else ""))
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
    if pending_here():
        st.rerun()  # show the new approval requests in the sidebar

persist()  # runs that end normally save here; runs ending in st.rerun() are saved at the top of the next run
