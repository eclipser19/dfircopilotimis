import json
import os
import re

import streamlit as st
from langchain_core.messages import HumanMessage, SystemMessage

from streamlit.runtime.scriptrunner import get_script_run_ctx

from copilot import (approvals, auth, cases, citations, collection, commands, conversation, knowledge, lessons,
                     memory, outputs, session)
from copilot import llm as llm_config
from copilot.agent import TokenUsage, run_turn, status_line
from copilot.case_config import case_config
from copilot.database import case_db
from copilot.prompts import build_system_prompt
from copilot.tools import tools

st.set_page_config(page_title="DFIR Copilot", page_icon="🕵️", layout="wide")
# Long evidence values (base64, paths) wrap inside tables instead of widening them.
st.markdown("<style>[data-testid='stTable'] td:last-child, [data-testid='stTable'] td:last-child * "
            "{overflow-wrap: anywhere !important; word-break: break-word !important;}</style>", unsafe_allow_html=True)


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
        st.error("Sign-in is required (login.required) but no accounts exist yet. On the server, run "
                 "`python -m copilot.auth add <username> --admin`.")
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
USER = st.session_state.get("user")      # None when the app runs without accounts


# ==========================================
# This browser session's own active case (see copilot/session.py)
# ==========================================
def _browser_session():
    """The copilot session of the browser session running this code (None outside a browser run)."""
    if get_script_run_ctx(suppress_warning=True) is None:
        return None
    current = st.session_state.get("dfir")
    if current is None:
        raise session.NoCase("No case is open in this browser session.")
    return current


session.PROVIDER = _browser_session
if "dfir" not in st.session_state:
    st.session_state.dfir = cases.new_session(USER)

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
    messages, history = conversation.load(case_id, build_system_prompt(case_config), user=USER)
    st.session_state.case_id = case_id
    st.session_state.messages = messages      # [{role, content, log: [str], files: [output rows]}]
    st.session_state.chat_history = history
    st.session_state.triage_dismissed = False
    if note:
        st.session_state.messages.append({"role": "assistant", "content": note})


def persist():
    """Saves this session's conversation to the case it belongs to."""
    if "case_id" in st.session_state:
        conversation.save(st.session_state.case_id, st.session_state.messages, st.session_state.chat_history,
                          user=USER)


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


NO_IMAGE = "(none)"


def memory_fields(prefix: str, image: str = "", os_name: str = "windows"):
    """Memory image picker: the images in the server's memory folder (no local files needed)."""
    images = {i["name"]: i["size"] for i in memory.available_images()}
    if not memory.images_dir():
        st.caption("🧠 Memory analysis: set `memory.images_dir` in server.yaml to pick an image here.")
    options = [NO_IMAGE] + sorted(images) + ([image] if image and image not in images else [])
    c1, c2 = st.columns([3, 1])
    c1.selectbox("Memory image", options, index=options.index(image) if image else 0, key=prefix + "mem",
                 format_func=lambda n: n if n == NO_IMAGE else
                 f"{n} ({memory.human_size(images[n])})" if n in images else f"{n} (missing)",
                 help="Analyzed with Volatility 3. Images are files in the server's memory folder.")
    c2.selectbox("OS", ["windows", "linux"], index=1 if os_name == "linux" else 0, key=prefix + "mem_os")


def _picked_image(prefix: str) -> str:
    value = st.session_state.get(prefix + "mem", NO_IMAGE)
    return "" if value in (None, NO_IMAGE) else value


def create_case_cb():
    st.session_state.nc_error = ""
    case_id = st.session_state.get("nc_id", "").strip()
    copy_from = st.session_state.get("nc_copy")
    try:
        cases.create(case_id, st.session_state.get("nc_name", "").strip(),
                     st.session_state.get("nc_client", "").strip(), st.session_state.get("nc_start", "").strip(),
                     st.session_state.get("nc_end", "").strip(), st.session_state.get("nc_desc", "").strip(),
                     int(st.session_state.get("nc_offset", 0)), _ioc_values("nc_"),
                     None if copy_from in (None, "(none)") else copy_from,
                     memory_image=_picked_image("nc_"), memory_os=st.session_state.get("nc_mem_os", "windows"))
        cases.switch(case_id)
    except cases.CaseError as e:
        st.session_state.nc_error = str(e)
        return
    for key in [k for k in st.session_state if str(k).startswith("nc_")]:
        del st.session_state[key]
    if copy_from not in (None, "(none)"):
        st.session_state.case_note = f" Collected data copied from `{copy_from}`."


def save_access_cb(case_id: str):
    p = f"ac_{case_id}_"
    try:
        cases.set_access(case_id, members=st.session_state.get(p + "members", []),
                         owner=st.session_state.get(p + "owner") if auth.is_admin(USER) else None)
    except cases.CaseError as e:
        st.session_state.ac_message = f"❌ {e}"
        return
    st.session_state.ac_message = "✅ Access saved."


def save_settings_cb(case_id: str):
    p = f"cs_{case_id}_"
    try:
        cases.update(case_id, name=st.session_state[p + "name"], client_id=st.session_state[p + "client"],
                     start_time=st.session_state[p + "start"], end_time=st.session_state[p + "end"],
                     clock_offset_minutes=int(st.session_state[p + "offset"]),
                     description=st.session_state[p + "desc"], iocs=_ioc_values(p),
                     memory_image=_picked_image(p), memory_os=st.session_state.get(p + "mem_os", "windows"))
    except cases.CaseError as e:
        st.session_state.cs_message = f"❌ {e}"
        return
    cases.consume_settings_change()
    st.session_state.chat_history[0] = SystemMessage(content=build_system_prompt(case_config))
    st.session_state.cs_message = "✅ Saved. The agent now works with the new settings."


def new_case_form():
    st.caption("Fields marked * are required. The client ID can be added later, but is needed to collect.")
    st.text_input("Case ID *", placeholder="acme-ws42", key="nc_id", help="Folder name: letters, digits, - and _")
    st.text_input("Name *", placeholder="ACME workstation 42", key="nc_name")
    st.text_input("Velociraptor client ID", placeholder="C.1234abcd...", key="nc_client")
    c1, c2 = st.columns(2)
    c1.text_input("Window start (UTC)", placeholder="2024-01-15T00:00:00Z", key="nc_start")
    c2.text_input("Window end (UTC)", placeholder="2024-01-17T00:00:00Z", key="nc_end")
    st.number_input("Host clock ahead of UTC (minutes)", value=0, step=15, key="nc_offset")
    st.text_area("What happened / what to find out", key="nc_desc")
    memory_fields("nc_")
    ioc_fields("nc_")
    sources = ["(none)"] + [c["id"] for c in cases.list_cases() if c["has_data"]]
    st.selectbox("Copy collected data from", sources, key="nc_copy",
                 help="Only cases on the same evidence client. Findings are not copied.")
    st.button("Create and open", type="primary", on_click=create_case_cb)
    if st.session_state.get("nc_error"):
        st.error(st.session_state.nc_error)


def account_box():
    if USER:
        c1, c2 = st.columns([3, 2])
        c1.caption(f"👤 Signed in as **{USER}**" + (" (admin)" if auth.is_admin(USER) else ""))
        if c2.button("Sign out"):
            persist()
            st.session_state.clear()      # drops this browser's case session (and its connection)
            st.rerun()
    else:
        st.warning("No sign-in configured: anyone who can reach this page can use it. "
                   "Add an account with `python -m copilot.auth add <username> --admin`.")


def llm_box():
    # A server-side key is used directly and never sent to the browser (a pre-filled password
    # field is readable by every visitor). A local model needs no key at all. Only a cloud
    # endpoint without a server key asks each investigator for theirs.
    user_key = ""
    if llm_config.needs_user_key():
        user_key = st.text_input("API key for the LLM endpoint", type="password")
    elif llm_config.is_local():
        st.caption(f"🖥️ Local model `{llm_config.model_name()}` at {llm_config.base_url()}")
    else:
        st.caption(f"🔑 Model `{llm_config.model_name()}`, using the server's API key.")
    key = user_key or ("" if llm_config.needs_user_key() else "server")
    # Rebuilt when the key or the model settings change (server.yaml is re-read on every run).
    key_id = key and f"{key}|{llm_config.base_url()}|{llm_config.model_name()}"
    if key_id and ("llm_with_tools" not in st.session_state or st.session_state.get("current_api_key") != key_id):
        # Kept in this browser session only; never written to os.environ.
        st.session_state.current_api_key = key_id
        llm = llm_config.make_llm(user_key or None)
        st.session_state.llm = llm
        st.session_state.llm_with_tools = llm.bind_tools(tools)
        st.session_state.finalizer = llm.bind_tools(tools, tool_choice="none")


def server_artifacts():
    """Artifact names on the Velociraptor server, read once per browser session (None if unreachable)."""
    if "server_artifacts" not in st.session_state:
        names = None
        try:
            res = collection.get_vql().run_vql("SELECT name FROM artifact_definitions()", timeout=5)
            names = sorted({r["name"] for r in res.get("results", []) if isinstance(r, dict) and r.get("name")})
        except Exception:      # no api_client.yaml, server down...: offer the suggestions only
            names = None
        st.session_state.server_artifacts = names or None
    return st.session_state.server_artifacts


def _plan_params_text() -> str:
    params = {step["artifact"]: step["parameters"] for step in case_config.collection_plan if step["parameters"]}
    return json.dumps(params, indent=1) if params else ""


def picked_triage(prefix: str) -> list:
    """The disk triage chosen in this session (else the case's) as [{artifact, parameters}]; ValueError if bad."""
    plan = case_config.collection_plan
    picked = st.session_state.get(prefix + "sel", [step["artifact"] for step in plan])
    text = st.session_state.get(prefix + "paramtext", _plan_params_text()).strip()
    try:
        given = json.loads(text) if text else {}
    except ValueError as e:
        raise ValueError(f"Parameters are not valid JSON: {e}")
    if not isinstance(given, dict) or not all(isinstance(v, dict) for v in given.values()):
        raise ValueError('Parameters must look like {"Artifact.Name": {"Param": "value"}}.')
    known = {s["artifact"]: s["parameters"] for s in knowledge.triage_suggestions()}
    known.update({step["artifact"]: step["parameters"] for step in plan})
    return [{"artifact": n, "parameters": dict(given[n]) if n in given else dict(known.get(n) or {})} for n in picked]


def picked_memory(prefix: str) -> list:
    return st.session_state.get(prefix + "memsel", memory.triage_plan())


def save_triage_cb(case_id: str):
    p = f"tri_{case_id}_"
    try:
        changes = {"collect": [step if step["parameters"] else step["artifact"] for step in picked_triage(p)]}
        if case_config.memory_image:
            changes["memory_collect"] = picked_memory(p)
        cases.update(case_id, **changes)
    except (ValueError, cases.CaseError) as e:
        st.session_state.tri_message = f"❌ {e}"
        return
    cases.consume_settings_change()
    st.session_state.tri_message = "✅ Saved as this case's triage."


def reset_triage_cb(case_id: str):
    p = f"tri_{case_id}_"
    for key in ("sel", "paramtext", "memsel", "art", "params", "mem"):
        st.session_state.pop(p + key, None)
    st.session_state.tri_message = "Back to the case's triage list."


def _keep(widget_key: str, key: str):
    """Copies an editor widget's value to a plain key, which outlives the widget (and the sidebar,
    drawn first, sees the new value in the same run)."""
    st.session_state[key] = st.session_state[widget_key]


def lesson_cb(kind: str, lesson_id: str = None):
    """Investigator actions on lessons: add, accept, remove (admins only when sign-in is used)."""
    try:
        if kind == "add":
            lesson = lessons.add(st.session_state.get("ln_topic", ""), st.session_state.get("ln_text", ""),
                                 st.session_state.get("ln_unusable", False), source="investigator", approver=USER,
                                 case=cases.current_id())
            for key in ("ln_topic", "ln_text", "ln_unusable"):
                st.session_state.pop(key, None)
            st.session_state.ln_message = ("✅ Lesson saved." if lesson["status"] == "active" else
                                           "✅ Saved as proposed: an admin must accept it.")
        elif kind == "accept":
            lessons.accept(lesson_id, approver=USER)
            st.session_state.ln_message = "✅ Accepted."
        elif kind == "remove":
            lessons.remove(lesson_id, approver=USER)
            st.session_state.ln_message = "Removed."
    except lessons.LessonError as e:
        st.session_state.ln_message = f"❌ {e}"


def knowledge_panel():
    """Lessons learned on this server (shared by every case): review, add, remove."""
    trusted = USER is None or auth.is_admin(USER)
    active, waiting = lessons.active(), lessons.proposed()
    with st.expander(f"🧠 Knowledge · {len(active)} lesson{'' if len(active) == 1 else 's'}"
                     + (f" · {len(waiting)} proposed" if waiting else ""), expanded=False):
        st.caption("Notes the agent reads in every case on this server: which artifacts fail on disk images, "
                   "parameters that work, how to read certain records. The agent proposes them in the chat "
                   "(you approve them under ⏳ Awaiting your approval), or you write one here.")
        for lesson in active:
            st.caption(citations.md_literal(lessons.summary(lesson)) +
                       f" · *{lesson.get('approved_by') or lesson.get('source')}*")
            if trusted:
                st.button("Remove", key=f"ln-del-{lesson['id']}", on_click=lesson_cb, args=("remove", lesson["id"]))
        if waiting:
            st.markdown("**Proposed, waiting for an admin**")
            for lesson in waiting:
                st.caption(citations.md_literal(lessons.summary(lesson)))
                if trusted:
                    c1, c2 = st.columns(2)
                    c1.button("Accept", key=f"ln-ok-{lesson['id']}", on_click=lesson_cb, args=("accept", lesson["id"]))
                    c2.button("Remove", key=f"ln-no-{lesson['id']}", on_click=lesson_cb, args=("remove", lesson["id"]))
        if st.toggle("✍️ Write a lesson yourself", key="ln_open"):
            st.caption("It applies to the agent right away" +
                       ("." if trusted else " once an admin accepts it.") + " Keep it general: no case details.")
            st.text_input("Topic: an artifact, playbook or subject", key="ln_topic",
                          placeholder="e.g. Windows.Applications.Chrome.History")
            st.text_area("Lesson", key="ln_text", height=80,
                         placeholder="e.g. Returns 0 rows on disk images: it calls lookupSID (see the flow log).")
            st.checkbox("This artifact does not work on disk images (the copilot will refuse it)", key="ln_unusable")
            st.button("Save lesson", on_click=lesson_cb, args=("add",))
        if st.session_state.get("ln_message"):
            st.caption(st.session_state.ln_message)


def set_triage_editing(on: bool):
    st.session_state.triage_editing = on


def triage_panel():
    """Sidebar: what the triage will collect, and the buttons to run it (the editor is in the main area)."""
    action = None
    p = f"tri_{cases.current_id()}_"
    try:
        chosen, problem = picked_triage(p), ""
    except ValueError as e:
        chosen, problem = [], str(e)
    st.caption(f"**Disk** · {len(chosen)} artifact{'s' if len(chosen) != 1 else ''}")
    for step in chosen:
        st.caption(citations.md_literal(f"• {step['artifact']}" + (" (with parameters)" if step["parameters"] else "")))
    if problem:
        st.error(problem)
    plugins = picked_memory(p) if case_config.memory_image else []
    if case_config.memory_image:
        st.caption(f"**Memory** · {case_config.memory_image}")
        st.caption(citations.md_literal(", ".join(plugins) or "no plugins"))
    st.button("✏️ Choose what to collect", key="tri_edit", on_click=set_triage_editing, args=(True,),
              help="Opens the triage list above the chat: suggestions for disk images and every artifact "
                   "on your Velociraptor server.")
    analyze = st.checkbox("Analyze with the agent afterwards", value=True, key="triage_analyze")
    c1, c2 = st.columns(2)
    if c1.button("Run triage", key=p + "run",
                 disabled=bool(case_config.client_id_error) or not chosen or bool(problem)):
        action = ("triage", (analyze, chosen))
    if case_config.memory_image and c2.button("Run memory triage", key=p + "run_mem", disabled=not plugins):
        action = ("memory_triage", (analyze, plugins))
    return action


def triage_editor():
    """Main area, full width: choose the triage artifacts and memory plugins, then save or just use them."""
    cid = cases.current_id()
    p = f"tri_{cid}_"
    plan = case_config.collection_plan
    planned = [step["artifact"] for step in plan]
    suggestions = {s["artifact"]: s for s in knowledge.triage_suggestions()}
    server = server_artifacts()
    pool = server if server is not None else list(suggestions)
    usable = [n for n in pool if case_config.is_artifact_allowed(n) and not knowledge.is_live_only(n)]
    current = st.session_state.get(p + "sel", planned)
    options = list(dict.fromkeys(current + planned + [n for n in suggestions if n in usable] +
                                 sorted(n for n in usable if n not in suggestions)))
    with st.container(border=True):
        st.markdown(f"#### 🧰 Triage for case `{cid}`")
        st.caption("⭐ = suggested for disk images (reads files, registry or event logs). " +
                   (f"{len(usable)} artifacts on your Velociraptor server are allowed in this case; type to search."
                    if server is not None else "Velociraptor is not reachable, so only the suggestions are listed."))
        st.session_state[p + "sel"] = st.multiselect(
            "Disk artifacts", options, default=current, key=p + "art", on_change=_keep, args=(p + "art", p + "sel"),
            format_func=lambda n: f"{'⭐ ' if n in suggestions else ''}{n}{' (heavy)' if case_config.is_heavy(n) else ''}")
        st.session_state[p + "paramtext"] = st.text_area(
            "Parameters (JSON, optional)", value=st.session_state.get(p + "paramtext", _plan_params_text()),
            key=p + "params", height=110, on_change=_keep, args=(p + "params", p + "paramtext"),
            help='e.g. {"Windows.EventLogs.EvtxHunter": {"IdRegex": "^(4624|7045)$"}}. Artifacts not listed here '
                 'keep their saved or suggested parameters; {} means none.')
        try:
            chosen, problem = picked_triage(p), ""
        except ValueError as e:
            chosen, problem = [], str(e)
        for step in chosen:
            why = suggestions.get(step["artifact"], {}).get("why", "")
            given = f" · parameters {json.dumps(step['parameters'])}" if step["parameters"] else ""
            st.caption(citations.md_literal(f"{step['artifact']}{' · ' + why if why else ''}{given}"))
        if problem:
            st.error(problem)
        if any(case_config.is_heavy(step["artifact"]) and not step["parameters"] for step in chosen):
            st.caption(f"⚠️ Heavy artifacts without a filter stop at {case_config.max_rows:,} rows.")
        if case_config.memory_image:
            mem_options = memory.triage_plugins()
            st.session_state[p + "memsel"] = st.multiselect(
                f"Memory plugins ({case_config.memory_image})", mem_options, key=p + "mem",
                on_change=_keep, args=(p + "mem", p + "memsel"),
                default=[x for x in picked_memory(p) if x in mem_options],
                help="Run with Volatility 3 on the case's memory image.")
        c1, c2, c3 = st.columns([2, 2, 1])
        c1.button("💾 Save as this case's triage", key=p + "save", on_click=save_triage_cb, args=(cid,),
                  disabled=bool(problem), help="Stored in the case file: used next time and by the CLI.")
        c2.button("↩️ Back to the case's list", key=p + "reset", on_click=reset_triage_cb, args=(cid,))
        c3.button("Done", key="tri_done", on_click=set_triage_editing, args=(False,), type="primary")
        st.caption("Without saving, the choice is used for this session only. Run it from the sidebar.")
        if st.session_state.get("tri_message"):
            st.caption(st.session_state.tri_message)


# The hook is process-wide, but queue_request stores each request in the session that made it.
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


def cited_box(content: str):
    """What the evidence and finding IDs in an answer are, looked up in the case database (no LLM)."""
    found = citations.cited(content, case_db, case_config)
    if not (found["evidence"] or found["findings"]):
        return
    with st.expander(f"🔎 Cited in this answer: {citations.summary(found)}", expanded=False):
        # st.table renders cells as Markdown: evidence text must stay literal (no links, images or math).
        for rows in (found["findings"], found["evidence"]):
            if rows:
                st.table([{k: citations.md_literal(v) for k, v in row.items()} for row in rows])


def render_message(msg: dict, index: int):
    with st.chat_message(msg["role"]):
        if msg.get("log"):
            with st.expander("Steps", expanded=False):
                st.text("\n".join(msg["log"]))
        if msg.get("content"):
            st.markdown(citations.answer_markdown(msg["content"]))
            if msg["role"] == "assistant":
                cited_box(msg["content"])
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
            st.markdown(citations.answer_markdown(text))
    # Questions typed by the investigator get the matching playbooks attached (automatic prompts don't).
    st.session_state.chat_history.append(HumanMessage(content=knowledge.with_playbooks(text) if show_user else text))
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
        st.markdown(citations.answer_markdown(content))
        cited_box(content)
        for entry in files:
            download_button(entry, key=f"dl-new-{entry['output_id']}")
        st.caption(st.session_state.usage.summary())
    st.session_state.messages.append({"role": "assistant", "content": content, "log": log, "files": files})


def run_triage(analyze: bool, plan: list = None):
    """The triage collections (picked in the sidebar, else the case's), no LLM; then optionally an agent turn."""
    lines, summaries = [], []
    with st.chat_message("assistant"):
        status = st.status("Running triage collection...", expanded=True)
        for step in plan or case_config.collection_plan:
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


def run_memory_triage(analyze: bool, plugins: list = None):
    """The memory triage plugins (picked in the sidebar, else the case's), no LLM; then optionally an agent turn."""
    lines = []
    with st.chat_message("assistant"):
        status = st.status("Running memory triage (each plugin can take minutes)...", expanded=True)

        def progress(plugin):
            status.write(f"Running `{plugin}`...")

        summaries = memory.triage(progress=progress, plugins=plugins)
        for summary in summaries:
            lines.append(status_line(summary))
            status.text(lines[-1])
        status.update(label="Memory triage finished", state="complete", expanded=False)
    st.session_state.messages.append({"role": "assistant",
                                      "content": "**Memory triage**\n\n```\n" + "\n".join(lines) + "\n```"})
    if not (analyze and any(s.get("state") == "FINISHED" for s in summaries)):
        st.rerun()
    agent_turn(
        "The memory triage has been run for you on the case's memory image. Results per plugin:\n"
        f"{json.dumps(summaries, indent=2)}\n"
        "Analyze the memory evidence: processes with odd names, parents or paths (pslist/pstree), processes "
        "in psscan but not pslist, command lines, external network connections (netscan) and their owning "
        "process, malfind hits, unusual services. Search for the case IOCs and correlate with the disk "
        "timeline if there is one.",
        show_user=False)


def resolve_request(request: dict, approved: bool):
    """Runs (or declines) a queued agent request and tells the agent what happened."""
    st.session_state.pending = [r for r in st.session_state.pending if r["id"] != request["id"]]
    label = approvals.describe(request)
    if not approved:
        approvals.resolve(request, False, actor=USER)
        st.session_state.chat_history.append(HumanMessage(content=f"[Investigator] Declined: {label}."))
        st.session_state.messages.append({"role": "assistant", "content": f"❌ Declined — {label}"})
        return
    with st.chat_message("assistant"):
        with st.spinner(f"{label}..."):
            try:
                result = approvals.resolve(request, True, actor=USER)
            except (approvals.ApprovalError, collection.CollectionError, cases.CaseError) as e:
                result = f"Failed: {e}"
    shown = f"```\n{status_line(result)}\n```" if isinstance(result, dict) else str(result)
    st.session_state.chat_history.append(HumanMessage(
        content=f"[Investigator] Approved: {label}. Result: {json.dumps(result, default=str)}"))
    st.session_state.messages.append({"role": "assistant",
                                      "content": f"✅ Approved — {label}\n\n{shown}" +
                                                 ("" if st.session_state.get("auto_continue", True) else
                                                  "\n\nAsk the copilot to continue when ready.")})
    if cases.consume_settings_change():
        st.session_state.chat_history[0] = SystemMessage(content=build_system_prompt(case_config))


# ==========================================
# Every run: follow this session's active case
# ==========================================
lost = cases.refresh()          # reloads settings changed elsewhere; closes a case this user lost access to
if lost:
    st.session_state.pop("case_id", None)        # nothing more is saved to a case they can't open
    remaining = cases.list_cases()
    if remaining:
        cases.switch(remaining[0]["id"])
    st.session_state.case_note = f" ⚠️ {lost}"

if not st.session_state.dfir.has_case:
    # No case this user may open: offer to create one (or wait to be added to one).
    with st.sidebar:
        st.title("🕵️ DFIR Copilot")
        account_box()
        llm_box()
    st.title("Interactive Investigation")
    if lost:
        st.warning(lost)
    st.info("You have no case yet. Create one here, or ask a case owner or an admin to add you to theirs.")
    with st.container(border=True):
        new_case_form()
    st.stop()

# Save the conversation to its own case, then follow the active case if it changed
# (sidebar, /case, the agent, the New case form).
if "case_id" not in st.session_state:
    open_case_chat(st.session_state.pop("case_note", "").strip())
else:
    persist()
    if st.session_state.case_id != cases.current_id():
        previous = st.session_state.case_id
        restored = bool(conversation.load(cases.current_id(), "", user=USER)[0])
        open_case_chat((f"📁 **Back in case `{cases.current_id()}` — {case_config.case_name}.** Conversation restored."
                        if restored else
                        f"📁 **Now in case `{cases.current_id()}` — {case_config.case_name}.** New conversation.")
                       + f" (`{previous}` was saved.)" + st.session_state.pop("case_note", ""))
cases.consume_switch()
if cases.consume_settings_change():
    st.session_state.chat_history[0] = SystemMessage(content=build_system_prompt(case_config))

# ==========================================
# Sidebar
# ==========================================
action = None
with st.sidebar:
    st.title("🕵️ DFIR Copilot")
    account_box()
    llm_box()

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
        new_case_form()

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
            memory_fields(p, case_config.memory_image, case_config.memory_os)
            ioc_fields(p, case_config.iocs)
            st.button("Save settings", on_click=save_settings_cb, args=(cid,))
            if st.session_state.get("cs_message"):
                st.caption(st.session_state.cs_message)
    if USER:
        here = next((c for c in case_rows if c["id"] == current), {"owner": "", "members": []})
        with st.expander("👥 Access", expanded=False):
            st.caption(f"Owner: {here['owner'] or 'nobody (admins only)'}")
            p = f"ac_{current}_"
            if cases.can_manage(current):
                accounts = auth.usernames()
                if auth.is_admin(USER):
                    owners = [""] + accounts
                    st.selectbox("Owner", owners, index=owners.index(here["owner"]) if here["owner"] in owners else 0,
                                 format_func=lambda u: u or "(nobody: admins only)", key=p + "owner")
                st.multiselect("Members", [u for u in accounts if u != here["owner"]],
                               default=[m for m in here["members"] if m in accounts], key=p + "members",
                               help="They can open this case, its data, findings and files. "
                                    "Each keeps their own chat.")
                st.button("Save access", on_click=save_access_cb, args=(current,))
            else:
                st.caption(f"Members: {', '.join(here['members']) or 'none'}. The owner or an admin can change this.")
            if st.session_state.get("ac_message"):
                st.caption(st.session_state.ac_message)
    if st.button("🧹 New conversation", help="Clears this case's chat and the agent's memory of it. "
                                          "Collected data and findings stay."):
        conversation.clear(cases.current_id(), user=USER)
        open_case_chat()
        st.rerun()
    st.text(f"{case_config.case_name}\nAnalyst: {case_config.analyst}")
    if case_config.client_id_error:
        st.warning(case_config.client_id_error)
    else:
        st.text(f"Evidence client: {case_config.client_id}")
    if case_config.memory_image:
        st.text(f"Memory image: {case_config.memory_image}")
    if case_config.has_scope:
        st.text(f"Window: {case_config.start_time}\n     to {case_config.end_time}")
    if case_config.clock_offset_minutes:
        st.caption(f"Host clock offset: {case_config.clock_offset_minutes:+d} min")
    st.caption(f"LLM tokens this session: "
               f"{st.session_state.usage.session_input + st.session_state.usage.session_output:,}")

    st.divider()
    with st.expander("🧰 Triage collection", expanded=False):
        action = triage_panel() or action

    if pending_here():
        st.divider()
        st.subheader("⏳ Awaiting your approval")
        st.caption("The agent asked to change something. Nothing happens until you approve.")
        for req in pending_here():
            st.markdown(f"**{approvals.ACTIONS.get(req['kind'], req['kind']).capitalize()}**")
            st.caption(citations.md_literal(req["summary"]))      # exactly what is asked, never rendered
            shown = req["details"].get("params") or req["details"].get("options")
            if req["kind"] in ("collect", "memory") and shown:
                st.code(json.dumps(shown, indent=1), language="json")
            if req["kind"] == "lesson":
                st.caption("⚠️ Lessons apply to every case on this server. Approve only if it is general and true.")
            c1, c2 = st.columns(2)
            if c1.button("Approve", key=f"approve-{req['id']}"):
                action = ("approve", req)
            if c2.button("Deny", key=f"deny-{req['id']}"):
                action = ("deny", req)
        if len(pending_here()) > 1 and st.button("✅ Approve all", key="approve-all", type="primary"):
            action = ("approve_all", None)
        st.checkbox("Continue the agent once all are decided", value=True, key="auto_continue",
                    help="Otherwise ask the copilot to continue yourself.")

    st.divider()
    stats = case_db.get_stats()
    n = stats["total_records"]
    with st.expander(f"📊 Database · {n:,} record{'' if n == 1 else 's'}", expanded=False):
        st.caption(f"{stats['timeline_events']:,} timeline events · {stats['undated_records']:,} without timestamps")
        for src in stats["by_source"]:
            st.caption(f"- {src['source']} ({src['records']:,})")

    active = case_db.get_findings()
    with st.expander(f"🚩 Findings · {len(active)}", expanded=False):
        if not active:
            st.caption("No findings recorded yet.")
        for f in active:
            st.caption(f"[{(f['confidence'] or 'unknown').upper()}] {citations.md_literal(f['title'])}")
        if active and st.toggle("Retract a finding", key="retract_open"):
            labels = {f"{f['title']} ({f['finding_id']})": f["finding_id"] for f in active}
            choice = st.selectbox("Finding", list(labels), key="retract_choice")
            reason = st.text_input("Reason (e.g. the contradicting evidence)", key="retract_reason")
            if st.button("Retract", disabled=not reason.strip()):
                case_db.retract_finding(labels[choice], reason.strip() + (f" (retracted by {USER})" if USER else ""))
                st.session_state.chat_history.append(HumanMessage(
                    content=f"[Investigator] Retracted finding '{choice}': {reason.strip()}"))
                st.rerun()

    knowledge_panel()

    st.divider()
    st.subheader("📄 Report")
    chosen = st.multiselect("Report formats", ["html", "md"], default=case_config.report_formats,
                            key="report_formats", help="Formats cost no extra LLM tokens.")
    st.session_state.dfir.report_formats = chosen or None

    files = outputs.produced_since(0)
    if files:
        st.divider()
        with st.expander(f"📁 Files · {len(files)}", expanded=False):
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
if st.session_state.get("triage_editing"):
    triage_editor()

for i, msg in enumerate(st.session_state.messages):
    render_message(msg, i)

# First visit to an empty case: offer the triage collection (the CLI asks the same question).
if (not case_db.get_collections() and not st.session_state.triage_dismissed and action is None
        and (not case_config.client_id_error or case_config.memory_image)):
    with st.container(border=True):
        sources = (["the disk image (Velociraptor)"] if not case_config.client_id_error else []) + \
                  ([f"the memory image `{case_config.memory_image}` (Volatility)"] if case_config.memory_image else [])
        st.markdown(f"**No data collected for this case yet.** Run the initial triage of {' and '.join(sources)}? "
                    f"It needs no LLM; the agent can analyze the results afterwards.")
        c1, c2, c3 = st.columns([1, 1, 3])
        p = f"tri_{cases.current_id()}_"          # the same choice as the sidebar's triage panel
        if not case_config.client_id_error and c1.button("Run triage", type="primary"):
            try:
                plan = picked_triage(p)
            except ValueError:
                plan = None                        # unusable edits: the case's saved list
            action = ("triage", (st.session_state.get("triage_analyze", True), plan))
        if case_config.memory_image and c2.button("Run memory triage", type="primary", key="first_memory_triage"):
            action = ("memory_triage", (st.session_state.get("triage_analyze", True), picked_memory(p)))
        if c3.button("Skip"):
            st.session_state.triage_dismissed = True
            st.rerun()

if action:
    kind, arg = action
    if kind == "triage":
        st.session_state.triage_dismissed = True
        run_triage(*arg)
    elif kind == "memory_triage":
        st.session_state.triage_dismissed = True
        run_memory_triage(*arg)
    elif kind in ("approve", "deny", "approve_all"):
        for request in (pending_here() if kind == "approve_all" else [arg]):
            resolve_request(request, approved=(kind != "deny"))
        # Once nothing waits any more, the agent goes on with the results (no "continue" needed).
        if (st.session_state.get("auto_continue", True) and not pending_here()
                and st.session_state.case_id == cases.current_id() and "llm_with_tools" in st.session_state):
            agent_turn("[Investigator] Every pending request has been decided (see the results above). Continue "
                       "the investigation with them and answer the open question.", show_user=False)
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
