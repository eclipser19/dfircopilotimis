import json
import os
import re
import time

import streamlit as st

from streamlit.runtime.scriptrunner import get_script_run_ctx

from copilot import (approvals, auth, cases, citations, collection, commands, config_check, conversation, dossier,
                     established, feedback, jobs, knowledge, lessons, memory, outputs, report, session)
from copilot import llm as llm_config
from copilot.agent import TokenUsage
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
FOLLOW_EVERY = 0.3      # seconds between two looks at a running job's progress
if "usage" not in st.session_state:
    st.session_state.usage = TokenUsage()
    st.session_state.triage_dismissed = False


def open_case_chat(note: str = ""):
    """Follows the active case's conversation (saved in its database), with a note about the switch."""
    st.session_state.case_id = cases.current_id()
    st.session_state.triage_dismissed = False
    if note:
        conversation.append(st.session_state.case_id, {"role": "assistant", "content": note}, user=USER)


def load_chat():
    """The conversation as saved: background jobs add to it, so every run reads it. chat_history is what the
    agent's next turn starts from (fresh system prompt, the investigator's waiting notes)."""
    st.session_state.messages, st.session_state.chat_history = conversation.load(
        cases.current_id(), build_system_prompt(case_config), user=USER)


def tell_agent(text: str):
    """Something the investigator did that the agent should know, given to it at its next turn."""
    conversation.note_for_agent(cases.current_id(), text, user=USER)


def pending_here() -> list:
    """This investigator's agent requests waiting in the active case (kept in its database)."""
    return approvals.pending(USER)


def after_possible_switch():
    """Rerun when the active case or its settings changed (the top of the script does the rest)."""
    cases.consume_settings_change()
    if cases.consume_switch() or st.session_state.case_id != cases.current_id():
        st.rerun()


IOC_LABELS = {"ips": "IP addresses", "domains": "Domains", "hashes": "Hashes", "filenames": "File names",
              "users": "Accounts"}


def ioc_fields(prefix: str, initial: dict = None, columns: int = 1):
    """IOC text areas (one value per line) with free and AI extraction from the description."""
    st.markdown("**IOCs** (one per line)")
    c1, c2 = st.columns(2)
    c1.button("Extract from description", key=prefix + "extract", on_click=extract_iocs_cb, args=(prefix, False),
              help="Pattern based, free: IPs, domains, hashes, file names, accounts (also defanged).")
    c2.button("✨ AI extract", key=prefix + "ai_extract", on_click=extract_iocs_cb, args=(prefix, True),
              disabled="llm" not in st.session_state,
              help="One small LLM call; catches what patterns miss. Values are checked against the text.")
    slots = st.columns(columns)
    for i, (kind, label) in enumerate(IOC_LABELS.items()):
        slots[i % columns].text_area(label, value="\n".join((initial or {}).get(kind, [])), key=f"{prefix}ioc_{kind}",
                                     height=68)


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
NO_CASE = "(none)"
SHARE_MODES = ["Nobody", "Chosen accounts", "Everyone on this server"]


def _case_label(c: dict) -> str:
    """A case in a picker: its ID, name, and who shares it if it isn't one of the user's own."""
    evidence = c["client_id"] or c["memory_image"] or "no evidence set"
    return f"{c['id']} — {c['name']} ({evidence}" + (f"; shared by {c['owner'] or 'an admin'})" if c["shared"] else ")")


def memory_fields(prefix: str, image: str = "", os_name: str = "windows", locked: bool = False):
    """Memory image picker: the images in the server's memory folder this investigator may use
    (no local files needed). Locked once the case holds data from its image."""
    images = {i["name"]: i["size"] for i in cases.usable_memory_images()}
    if not memory.images_dir():
        st.caption("🧠 Memory analysis: set `memory.images_dir` in server.yaml to pick an image here.")
    options = [NO_IMAGE] + sorted(images) + ([image] if image and image not in images else [])
    c1, c2 = st.columns([3, 1])
    c1.selectbox("Memory image", options, index=options.index(image) if image else 0, key=prefix + "mem",
                 format_func=lambda n: n if n == NO_IMAGE else
                 f"{n} ({memory.human_size(images[n])})" if n in images else f"{n} (missing)",
                 disabled=locked,
                 help="Analyzed with Volatility 3. Images are files in the server's memory folder." +
                      (" Locked: this case holds data from it." if locked else ""))
    c2.selectbox("OS", ["windows", "linux"], index=1 if os_name == "linux" else 0, key=prefix + "mem_os")


def _picked_image(prefix: str) -> str:
    value = st.session_state.get(prefix + "mem", NO_IMAGE)
    return "" if value in (None, NO_IMAGE) else value


def create_case_cb():
    st.session_state.nc_error = ""
    case_id = st.session_state.get("nc_id", "").strip()
    copy_from = st.session_state.get("nc_copy")
    copy_from = None if copy_from in (None, NO_CASE) else copy_from
    with_findings = bool(copy_from and st.session_state.get("nc_copy_findings"))
    try:
        cases.create(case_id, st.session_state.get("nc_name", "").strip(),
                     st.session_state.get("nc_client", "").strip(), st.session_state.get("nc_start", "").strip(),
                     st.session_state.get("nc_end", "").strip(), st.session_state.get("nc_desc", "").strip(),
                     int(st.session_state.get("nc_offset", 0)), _ioc_values("nc_"), copy_from,
                     memory_image=_picked_image("nc_"), memory_os=st.session_state.get("nc_mem_os", "windows"),
                     copy_findings=with_findings)
        cases.switch(case_id)
    except cases.CaseError as e:
        st.session_state.nc_error = str(e)
        return
    for key in [k for k in st.session_state if str(k).startswith("nc_")]:
        del st.session_state[key]
    if copy_from:
        st.session_state.case_note = (f" Collected data{', findings and dossier' if with_findings else ''} "
                                      f"copied from `{copy_from}`.")


def import_cb(case_id: str):
    """Copies another case's collected data (and findings) into this one: the investigator's own action."""
    p = f"cs_{case_id}_"
    source, with_findings = st.session_state.get(p + "imp"), bool(st.session_state.get(p + "imp_findings"))
    try:
        counts = cases.copy_data(source, case_id, findings=with_findings)
    except cases.CaseError as e:
        st.session_state.cs_message = f"❌ {e}"
        return
    what = f"{counts['records']:,} new records" + (f", {counts['findings']} findings" if with_findings else "") + \
        (", its dossier" if counts.get("dossier") else "")
    st.session_state.cs_message = f"✅ Imported from `{source}`: {what}."
    tell_agent(f"[Investigator] Imported from case {source} into this case: {what}.")


def save_sharing_cb(case_id: str):
    p = f"ac_{case_id}_"
    mode = st.session_state.get(p + "share_mode", SHARE_MODES[0])
    shared = [] if mode == SHARE_MODES[0] else [cases.EVERYONE] if mode == SHARE_MODES[2] else \
        st.session_state.get(p + "share_with", [])
    try:
        cases.set_sharing(case_id, shared, findings=bool(st.session_state.get(p + "share_findings")))
    except cases.CaseError as e:
        st.session_state.ac_message = f"❌ {e}"
        return
    st.session_state.ac_message = "✅ Sharing saved." if shared or mode == SHARE_MODES[0] else \
        "✅ Saved: pick the accounts to share with."


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
                     memory_image=_picked_image(p), memory_os=st.session_state.get(p + "mem_os", "windows"),
                     evidence={"image_name": st.session_state.get(p + "img", ""),
                               "image_sha256": st.session_state.get(p + "sha", "")})
    except cases.CaseError as e:
        st.session_state.cs_message = f"❌ {e}"
        return
    cases.consume_settings_change()
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
    reusable = {c["id"]: c for c in cases.reusable_cases()}
    st.selectbox("Start from another case's data", [NO_CASE] + list(reusable), key="nc_copy",
                 format_func=lambda i: i if i == NO_CASE else _case_label(reusable[i]),
                 help="Your cases and those shared with you. The new case gets that case's evidence (client and "
                      "memory image) and a copy of its collected data, so nothing is collected twice.")
    picked = reusable.get(st.session_state.get("nc_copy"))
    st.checkbox("Also copy its findings and dossier", key="nc_copy_findings",
                disabled=not (picked and picked["findings"]),
                help="Copied findings say which case they came from; review them for your case."
                     if not picked or picked["findings"] else "Its owner shares its collected data only.")
    st.button("Create and open", type="primary", on_click=create_case_cb)
    if st.session_state.get("nc_error"):
        st.error(st.session_state.nc_error)


def account_box():
    if USER:
        c1, c2 = st.columns([3, 2])
        c1.caption(f"👤 Signed in as **{USER}**" + (" (admin)" if auth.is_admin(USER) else ""))
        if c2.button("Sign out"):
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


# "Then investigate" is offered where the triage is started (sidebar panel, first-visit card); the
# checkboxes share one choice, kept in a plain key that outlives them.
INVESTIGATE_KEYS = ("triage_analyze", "first_investigate")


def _keep_investigate(key: str):
    st.session_state.investigate_after = st.session_state[key]
    for other in INVESTIGATE_KEYS:
        if other != key:
            st.session_state[other] = st.session_state[key]


def investigate_choice(key: str) -> bool:
    """The optional investigation after the triage: a checkbox that says what it costs."""
    if key not in st.session_state:
        st.session_state[key] = st.session_state.get("investigate_after", True)
    steps, tokens = dossier.budget()
    return st.checkbox("Then investigate the case (optional)", key=key, on_change=_keep_investigate, args=(key,),
                       help=f"One longer agent turn (up to {steps} steps / {tokens:,} tokens) reads everything "
                            f"collected and writes the case dossier every question starts from. Untick it to "
                            f"look at the data first: 🗂️ Case dossier or /investigate runs it later.")


def triage_panel():
    """Sidebar: what the triage will collect, and the buttons to run it (the editor is in the main area)."""
    action = None
    p = f"tri_{cases.current_id()}_"
    try:
        chosen, problem = picked_triage(p), ""
    except ValueError as e:
        chosen, problem = [], str(e)
    st.caption(f"**Disk** · {len(chosen)} artifact{'s' if len(chosen) != 1 else ''}")
    st.caption("  \n".join(citations.md_literal(f"• {step['artifact']}" + (" (with parameters)" if step["parameters"]
                                                                           else "")) for step in chosen))
    if problem:
        st.error(problem)
    plugins = picked_memory(p) if case_config.memory_image else []
    if case_config.memory_image:
        st.caption(f"**Memory** · {case_config.memory_image}")
        st.caption(citations.md_literal(", ".join(plugins) or "no plugins"))
    st.button("✏️ Choose what to collect", key="tri_edit", on_click=set_triage_editing, args=(True,),
              help="Opens the triage list below: suggestions for disk images and every artifact "
                   "on your Velociraptor server.")
    analyze = investigate_choice("triage_analyze")
    c1, c2 = st.columns(2)
    if c1.button("Run triage", key=p + "run", on_click=to_chat,
                 disabled=bool(case_config.client_id_error) or not chosen or bool(problem)):
        action = ("triage", (analyze, chosen))
    if case_config.memory_image and c2.button("Run memory triage", key=p + "run_mem", disabled=not plugins,
                                              on_click=to_chat):
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
        st.caption("Without saving, the choice is used for this session only. Run it with the buttons above.")
        if st.session_state.get("tri_message"):
            st.caption(st.session_state.tri_message)


# Agent requests wait in the case database for the investigator whose conversation asked.
approvals.ASK = approvals.queue


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
            # "literal": the app built it with md_literal already (approval results quote agent requests)
            st.markdown(msg["content"] if msg.get("literal") else citations.answer_markdown(msg["content"]))
            if msg["role"] == "assistant":
                cited_box(msg["content"])
        for entry in msg.get("files", []):
            download_button(entry, key=f"dl-{index}-{entry['output_id']}")
        if msg["role"] == "assistant" and msg.get("answer"):
            feedback_row(msg, index)


def feedback_cb(index: int):
    """A correction of an answer or dossier: becomes a note the agent takes as given."""
    msg = st.session_state.messages[index]
    st.session_state.fb_message_index = index
    try:
        entry = feedback.correct(msg.get("kind", "answer"), st.session_state.get(f"fb_text_{index}", ""),
                                 msg.get("question", ""), msg.get("content", ""))
    except feedback.FeedbackError as e:
        st.session_state.fb_message = f"❌ {e}"
        return
    conversation.update_message(cases.current_id(), index, user=USER,
                                rated={"by": USER or "", "comment": entry["comment"], "id": entry["feedback_id"]})
    st.session_state.fb_open = None
    extra = ""
    if st.session_state.get(f"fb_lesson_{index}"):
        try:
            lesson = lessons.add(st.session_state.get(f"fb_topic_{index}", ""), entry["comment"], source="investigator",
                                 approver=USER, case=cases.current_id())
            extra = (" Saved as a lesson for every case too." if lesson["status"] == "active" else
                     " Proposed as a lesson for every case: an admin accepts it.")
        except lessons.LessonError as e:
            extra = f" Not saved as a lesson: {e}"
    st.session_state.fb_message = "✅ The copilot takes this as given in this case from now on." + extra


def feedback_row(msg: dict, index: int):
    """👎 under an answer: investigators correct the copilot (copilot/feedback.py)."""
    rated = msg.get("rated")
    if rated and rated.get("rating", -1) < 0:          # chats saved before 👍 was removed may hold a positive one
        st.caption("👎 Corrected" +
                   (f" by {citations.md_literal(rated['by'])}" if rated.get("by") else "") +
                   (f": {citations.md_literal(rated['comment'])}" if rated.get("comment") else ""))
    else:
        if st.button("👎", key=f"fb_down_{index}", help="Wrong or incomplete: say what is right. The copilot takes "
                                                       "it as given in this case from now on."):
            st.session_state.fb_open = index
        if st.session_state.get("fb_open") == index:
            st.text_area("What is wrong, and what is right?", key=f"fb_text_{index}",
                         help="A fact or correction, e.g. 'the C2 connection belongs to the injected process, not the "
                              "dropper'. It goes into every conversation and investigation of this case.")
            if st.checkbox("Also propose it as a lesson for every case (how to read an artifact or a kind of "
                           "record, never a fact of this case)", key=f"fb_lesson_{index}"):
                st.text_input("Lesson topic (an artifact or a kind of question)", key=f"fb_topic_{index}")
            st.button("Save correction", key=f"fb_save_{index}", on_click=feedback_cb, args=(index,))
    if st.session_state.get("fb_message_index") == index and st.session_state.get("fb_message"):
        st.caption(st.session_state.fb_message)


def show_event(status, event: dict):
    """One step of a job's progress in its status box."""
    if event["kind"] == "tool":
        status.write(f"⚙️ `{event['text']}`")
    elif event["kind"] == "collection":
        status.text(event["text"])
    elif event["kind"] == "notice":
        status.warning(event["text"])
    else:
        status.write(event["text"])


def start(kind: str, payload: dict = None, retry: str = None) -> dict:
    """
    Starts background work for this investigator (copilot/jobs.py) and returns the job ({} if it could not
    start; the reason is shown). It runs in the server: leaving or reloading the page doesn't stop it.
    """
    payload = dict(payload or {})
    if retry:
        kind = jobs.get(retry).get("kind", "")
    model = st.session_state.get("llm_with_tools")
    if model is None and kind in ("ask", "investigate"):
        st.error("Enter the API key in the sidebar first.")
        return {}
    if kind == "triage" and payload.get("investigate") and model is None:
        payload["investigate"] = False
        st.info("The investigation needs the model: enter the API key, then run it from 🚩 Findings & dossier.")
    try:
        args = (st.session_state.get("llm_with_tools"), st.session_state.get("finalizer"), st.session_state.usage)
        job_id = jobs.retry(retry, *args) if retry else jobs.submit(kind, payload, *args)
    except jobs.JobError as e:
        st.error(str(e))
        return {}
    return jobs.get(job_id)


def follow(job: dict, question: str = ""):
    """
    Shows a job's progress until it ends, then reruns: the chat, header and tabs show what it added. The job
    goes on in the server if this page is closed or reloaded; the next page follows it from where it is.
    """
    if not job:
        return
    if question:
        with st.chat_message("user"):
            st.markdown(citations.answer_markdown(question))
    shown = 0
    with st.chat_message("assistant"):
        status = st.status(job["label"], expanded=True)
        while True:
            for event in jobs.events(job["job_id"], after=shown):
                shown = event["seq"]
                show_event(status, event)
            job = jobs.get(job["job_id"])
            if job["state"] not in jobs.ACTIVE:
                break
            time.sleep(FOLLOW_EVERY)
        if job["state"] == "done":
            status.update(label="Done", state="complete", expanded=False)
        else:
            status.update(label=f"Stopped: {job.get('error') or job['state']}", state="error", expanded=False)
    moved = (job.get("result") or {}).get("switch_to")
    if moved and moved != cases.current_id():
        cases.switch(moved)
    after_possible_switch()
    st.rerun()


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

# Follow the active case if it changed (sidebar, /case, the agent, the New case form). Conversations are
# saved as they change, so there is nothing to save here.
if "case_id" not in st.session_state:
    open_case_chat(st.session_state.pop("case_note", "").strip())
elif st.session_state.case_id != cases.current_id():
    previous = st.session_state.case_id
    restored = bool(conversation.messages(cases.current_id(), user=USER))
    open_case_chat((f"📁 **Back in case `{cases.current_id()}` — {case_config.case_name}.** Conversation restored."
                    if restored else
                    f"📁 **Now in case `{cases.current_id()}` — {case_config.case_name}.** New conversation.")
                   + f" (`{previous}` was saved.)" + st.session_state.pop("case_note", ""))
cases.consume_switch()
cases.consume_settings_change()
jobs.recover()            # work a stopped server was doing is marked interrupted (it can be continued)
load_chat()
running = jobs.active(USER)

# ==========================================
# Main-area views (one per tab)
# ==========================================
# Stable labels: a tab whose label changed would lose its selection.
TABS = ["💬 Chat", "🚩 Findings & dossier", "📥 Evidence & data", "📄 Report & files", "⚙️ Case"]


def to_chat():
    """Callback of buttons that start work: show the Chat tab, where its progress and results appear."""
    st.session_state.main_tab = TABS[0]


def _hosts() -> dict:
    """Host names per client from the records, cached per database state (a full scan on large cases)."""
    stamp = (cases.current_id(), case_db.get_stats()["total_records"])
    if st.session_state.get("hosts_stamp") != stamp:
        st.session_state.hosts_stamp, st.session_state.hosts = stamp, case_db.hosts_by_source()
    return st.session_state.hosts


def _when(value) -> str:
    """A case setting's time as "2020-09-18 00:00" (whatever form the case file holds it in)."""
    text = str(value or "").replace("T", " ").rstrip("Z")
    return text[:16] if len(text) >= 16 else text


def case_header(stats: dict, findings: list, notes: dict):
    """What this case is about and where it stands: evidence, window, data, findings, dossier."""
    st.title(f"🗂️ {case_config.case_name}")
    st.caption(f"Case `{cases.current_id()}` · analyst {citations.md_literal(case_config.analyst)} · "
               f"type `/help` in the chat for free commands")
    with st.container(border=True):
        c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
        c1.caption("EVIDENCE")
        if case_config.client_id_error:
            c1.markdown("💽 *no Velociraptor client set* (⚙️ Case)")
        else:
            client = case_config.client_id
            facts = [f"💽 `{client}`"] + [citations.md_literal(h) for h in _hosts().get(client, [])[:2]]
            if case_config.evidence.get("image_name"):
                facts.append(citations.md_literal(case_config.evidence["image_name"]))
            c1.markdown(" · ".join(facts))
        if case_config.memory_image:
            c1.markdown(f"🧠 {citations.md_literal(case_config.memory_image)}")
        c2.caption("INCIDENT WINDOW")
        c2.markdown(f"{_when(case_config.start_time)} →  \n{_when(case_config.end_time)} UTC" if case_config.has_scope
                    else "*not set*")
        if case_config.clock_offset_minutes:
            c2.caption(f"host clock {case_config.clock_offset_minutes:+d} min (times shown as true UTC + recorded)")
        collections = case_db.get_collections()
        running = sum(c.get("state") not in collection.TERMINAL_STATES for c in collections)
        c3.caption("DATA")
        c3.markdown(f"**{stats['total_records']:,}** records  \n"
                    f"{len(collections)} collection{'' if len(collections) == 1 else 's'}"
                    + (f" · ⏳ {running} running" if running else ""))
        c4.caption("FINDINGS · DOSSIER")
        c4.markdown(f"**{len(findings)}** finding{'' if len(findings) == 1 else 's'}  \n" +
                    (f"🗂️ dossier {notes['created_at'][11:16]} UTC" if notes else "no dossier yet"))


def note_cb(kind: str, feedback_id: int = None):
    try:
        if kind == "add":
            entry = feedback.add_note(st.session_state.get("note_text", ""))
            st.session_state.note_text = ""
            st.session_state.note_message = f"✅ Note {entry['feedback_id']} added: the copilot takes it as given."
        else:
            feedback.withdraw(feedback_id)
            st.session_state.note_message = f"Note {feedback_id} withdrawn."
    except feedback.FeedbackError as e:
        st.session_state.note_message = f"❌ {e}"


def confirm_cb(finding_id: str):
    try:
        found = feedback.confirm_finding(finding_id)
    except feedback.FeedbackError as e:
        st.session_state.note_message = f"❌ {e}"
        return
    tell_agent(f"[Investigator] Confirmed finding {found['finding_id']} ('{found['title']}') after checking its records.")


def findings_view(stats: dict, findings: list, notes: dict):
    """Investigator notes, the case dossier, and every finding with its records; confirming and retracting are
    the investigator's call."""
    action = None
    rows = feedback.notes()
    st.subheader(f"📝 Investigator notes · {len(rows)}")
    st.caption("Facts and corrections the copilot takes as given in this case, above the dossier and its own "
               "answers. Also `/note <text>` in the chat, or 👎 under an answer.")
    for r in rows:
        c1, c2 = st.columns([12, 1])
        c1.markdown(f"**{r['feedback_id']}** · {citations.md_literal(r.get('actor') or 'investigator')}: "
                    f"{citations.md_literal(r['comment'])}")
        c2.button("✖", key=f"note_rm_{r['feedback_id']}", on_click=note_cb, args=("remove", r["feedback_id"]),
                  help="Withdraw this note")
    c1, c2 = st.columns([6, 1])
    c1.text_input("New note", key="note_text", label_visibility="collapsed",
                  placeholder="A fact or correction, e.g. 'the 10.0.0.5 logons are the admin's own VPN'")
    c2.button("Add note", key="note_add", on_click=note_cb, args=("add",))
    if st.session_state.get("note_message"):
        st.caption(st.session_state.note_message)

    st.subheader("🗂️ Case dossier")
    if notes:
        st.caption(f"Written {notes['created_at'][:16].replace('T', ' ')} UTC by "
                   f"{citations.md_literal(notes['actor'] or 'the copilot')} · {notes['steps']} steps · "
                   f"{notes['tokens']:,} tokens · {notes['findings']} findings then")
        with st.container(border=True, height=420):
            st.markdown(re.sub(r"(?m)^#{1,3} ", "#### ", citations.answer_markdown(notes["text"])))
    else:
        st.caption("None yet. One longer agent turn reads everything collected and writes the case's timeline, "
                   "findings, hypotheses and gaps. Every question then starts from it: answers agree and cost less.")
    if st.button("🔎 Investigate again" if notes else "🔎 Investigate the case", key="investigate", on_click=to_chat,
                 disabled="llm_with_tools" not in st.session_state or not stats["total_records"],
                 help="Also `/investigate` in the chat. Runs as its own conversation; requests it makes "
                      "wait for approval as usual. Progress and the dossier appear in 💬 Chat."):
        action = ("investigate", None)
    kept = established.statements()
    if kept:
        with st.expander(f"Established in answers since the dossier · {len(kept)}"):
            st.caption("Statements answers backed with records the dossier does not cite, and searches they say came "
                       "back empty, kept by the code as written: every later question starts from them. Not reviewed; "
                       "a new investigation takes them into the dossier.")
            for s in kept:
                said = ("searched, nothing found: " if s["kind"] == "not_found" else "") + s["text"]
                st.markdown(f"- {citations.md_literal(said)}  \n  *asked:* {citations.md_literal(s['question'][:160])}")

    st.subheader(f"🚩 Findings · {len(findings)}")
    if not findings:
        st.caption("No findings recorded yet. The agent records them as it confirms what happened.")
        return action
    clock = report.Clock(case_config.clock_offset_minutes)
    st.dataframe([{"#": n, "UTC": clock.corrected(f["timestamp_utc"]), "Recorded": clock.recorded(f["timestamp_utc"]),
                   "Finding": f["title"], "Confidence": f["confidence"] or "", "MITRE": f["mitre_technique"] or "",
                   "Records": len(json.loads(f["evidence_ids"] or "[]")), "Confirmed by": f.get("confirmed_by") or "",
                   "Imported from": f.get("origin") or "", "ID": f["finding_id"]} for n, f in enumerate(findings, 1)],
                 hide_index=True, width="stretch")
    for n, f in enumerate(findings, 1):
        with st.expander(f"{n}. {'✅ ' if f.get('confirmed_by') else ''}{citations.md_literal(f['title'])}",
                         expanded=False):
            st.markdown(citations.md_literal(f["description"] or ""))
            if f.get("confirmed_by"):
                st.caption(f"✅ Confirmed by {citations.md_literal(f['confirmed_by'])}")
            else:
                st.button("✅ Confirm: I checked its records", key=f"confirm_{f['finding_id']}", on_click=confirm_cb,
                          args=(f["finding_id"],), help="The copilot then treats it as established, and the report "
                                                        "says who confirmed it.")
            found = citations.cited(" ".join(json.loads(f["evidence_ids"] or "[]")), case_db, case_config)
            if found["evidence"]:
                st.table([{k: citations.md_literal(v) for k, v in row.items()} for row in found["evidence"]])
    if st.toggle("Retract a finding", key="retract_open"):
        labels = {f"{f['title']} ({f['finding_id']})": f["finding_id"] for f in findings}
        choice = st.selectbox("Finding", list(labels), key="retract_choice")
        reason = st.text_input("Reason (e.g. the contradicting evidence)", key="retract_reason")
        if st.button("Retract", disabled=not reason.strip()):
            case_db.retract_finding(labels[choice], reason.strip() + (f" (retracted by {USER})" if USER else ""))
            tell_agent(f"[Investigator] Retracted finding '{choice}': {reason.strip()}")
            st.rerun()
    return action


def data_view(stats: dict):
    """Where the data came from, the triage, the collections, and a search that costs no tokens."""
    action = None
    st.subheader("💽 Evidence sources")
    sources, warnings = report.evidence_sources(case_db, case_config, hosts=_hosts())
    if sources:
        st.dataframe([{"Source": s["kind"], "Name": s["name"], "Identity": s["identity"],
                       "Collections": s["collections"], "Rows": s["rows"], "First collected (UTC)": s["first"],
                       "Last": s["last"]} for s in sources], hide_index=True, width="stretch")
    for warning in warnings:
        st.warning(citations.md_literal(warning))
    if not sources:
        st.caption("No evidence set: add the Velociraptor client or a memory image under ⚙️ Case.")

    st.subheader("🧰 Triage")
    action = triage_panel()
    if st.session_state.get("triage_editing"):
        triage_editor()

    collections = case_db.get_collections()
    st.subheader(f"📥 Collections · {len(collections)}")
    if collections:
        st.dataframe([{"Artifact": c["artifact"], "State": c["state"], "Rows": c["rows_ingested"],
                       "Started (UTC)": (c["requested_at"] or "")[:19].replace("T", " "), "Flow": c["flow_id"],
                       "Error": (c["error"] or "")[:200]} for c in reversed(collections)],
                     hide_index=True, width="stretch")

    st.subheader(f"🔎 Search the data · {stats['total_records']:,} records")
    st.caption(f"{stats['timeline_events']:,} timeline events · {stats['undated_records']:,} without timestamps · "
               "no LLM, no tokens")
    sources_by_name = ["(all sources)"] + [s["source"] for s in stats["by_source"]]
    c1, c2 = st.columns([3, 2])
    term = c1.text_input("Text, IP, account, file name, hash...", key="data_search")
    source = c2.selectbox("Source", sources_by_name, key="data_source",
                          format_func=lambda s: s if s == sources_by_name[0] else
                          f"{s} ({next(x['records'] for x in stats['by_source'] if x['source'] == s):,})")
    if 0 < len(term.strip()) < 3:
        st.caption("Type at least 3 characters (shorter ones can't use the search index and read every record).")
    elif term.strip():
        found = case_db.search_events(term.strip(), limit=500,
                                      source=None if source == sources_by_name[0] else source)
        clock = report.Clock(case_config.clock_offset_minutes)
        st.caption(f"{found['total']:,} records match" + (f"; showing the first {len(found['records'])}"
                                                          if found["total"] > len(found["records"]) else ""))
        st.dataframe([{"UTC": clock.corrected(r.get("first_seen")), "Recorded": clock.recorded(r.get("first_seen")),
                       "Source": r.get("source"), "Event": r.get("description"), "Evidence ID": r.get("evidence_id")}
                      for r in found["records"]], hide_index=True, width="stretch")
    return action


def report_view():
    """Report formats, writing the report, and every file produced for this case."""
    action = None
    st.subheader("📄 Report")
    st.caption("Built from the case database: findings, timeline, evidence sources, cited records and charts. "
               "Only the executive summary, correlations and recommendations come from the model.")
    chosen = st.multiselect("Formats", ["html", "md"], default=case_config.report_formats, key="report_formats",
                            help="Formats cost no extra LLM tokens.")
    st.session_state.dfir.report_formats = chosen or None
    if st.button("📝 Write the report", key="write_report", disabled="llm_with_tools" not in st.session_state or bool(running),
                 on_click=to_chat,
                 help="Asks the agent for the narrative and builds the report. It appears in 💬 Chat as a download."):
        action = ("ask", "Write the report for this case.")
    files = outputs.produced_since(0)
    st.subheader(f"📁 Files · {len(files)}")
    if files:
        st.caption(f"Saved in `{outputs.output_dir()}`")
        for entry in reversed(files[-30:]):
            download_button(entry, key=f"dl-side-{entry['output_id']}")
    else:
        st.caption("Reports and exports the agent produces appear here.")
    return action


def case_view(case_rows: list, current: str):
    """The case's settings, importing from other cases, and who may work on it or start from it."""
    if current == cases.LEGACY_ID:
        st.caption("This is the legacy root case.yaml: edit the file itself.")
    else:
        st.subheader("⚙️ Settings")
        cid = current
        p = f"cs_{cid}_"
        held = cases.collected_sources(cid)
        c1, c2 = st.columns(2)
        c1.text_input("Name *", value=case_config.case_name, key=p + "name")
        c2.text_input("Velociraptor client ID", value=case_config.client_id, key=p + "client",
                      disabled=bool(held["client"] and case_config.client_id),
                      help="The dead-disk client reading this case's image. Locked once the case holds data from it."
                      if held["client"] else "The dead-disk client reading this case's image (C.<hex>).")
        c1, c2 = st.columns(2)
        c1.text_input("Disk image file", value=case_config.evidence.get("image_name", ""), key=p + "img",
                      help="For the header and the report's evidence section.")
        c2.text_input("Disk image SHA-256", value=case_config.evidence.get("image_sha256", ""), key=p + "sha")
        c1, c2, c3 = st.columns([2, 2, 1])
        c1.text_input("Window start (UTC)", value=case_config.start_time, key=p + "start")
        c2.text_input("Window end (UTC)", value=case_config.end_time, key=p + "end")
        c3.number_input("Host clock ahead of UTC (min)", value=case_config.clock_offset_minutes,
                        step=15, key=p + "offset")
        st.text_area("Description", value=case_config.description, key=p + "desc")
        memory_fields(p, case_config.memory_image, case_config.memory_os,
                      locked=bool(held["memory"] and case_config.memory_image))
        ioc_fields(p, case_config.iocs, columns=3)
        st.button("Save settings", on_click=save_settings_cb, args=(cid,), type="primary")
        if st.session_state.get("cs_message"):
            st.caption(st.session_state.cs_message)

        st.subheader("📥 Import from another case")
        others = {c["id"]: c for c in cases.reusable_cases() if c["id"] != cid and (
            not c["client_id"] or not case_config.client_id or c["client_id"].lower() == case_config.client_id.lower())}
        if others:
            st.selectbox("Case on the same evidence", list(others), key=p + "imp",
                         format_func=lambda i: _case_label(others[i]))
            chosen = others.get(st.session_state.get(p + "imp"))
            st.checkbox("With its findings and dossier", key=p + "imp_findings",
                        disabled=not (chosen and chosen["findings"]))
            st.button("Import", key=p + "imp_go", on_click=import_cb, args=(cid,),
                      help="Adds its collected data to this case (records already here are not duplicated).")
        else:
            st.caption("No other case on this evidence has data you may use (yours, or shared with you).")
    if not USER:
        return
    here = next((c for c in case_rows if c["id"] == current), {"owner": "", "members": []})
    st.subheader("👥 Access")
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
                       help="They can open this case, its data, findings and files. Each keeps their own chat.")
        st.button("Save access", on_click=save_access_cb, args=(current,))
        shared, with_findings = cases.sharing_of(case_config.data)
        st.markdown("**Share its evidence**")
        mode = st.radio("Who may start their own case from this one's collected data", SHARE_MODES,
                        index=2 if shared == [cases.EVERYONE] else 1 if shared else 0, key=p + "share_mode",
                        help="They get a copy in a case of their own. They can't open this case, its chats, "
                             "files or audit log. Copies already made stay theirs if you stop sharing.")
        if mode == SHARE_MODES[1]:
            st.multiselect("Accounts", [u for u in accounts if u != here["owner"] and u not in here["members"]],
                           default=[u for u in shared if u in accounts], key=p + "share_with")
        st.checkbox("Include its findings and dossier", value=with_findings, key=p + "share_findings",
                    disabled=mode == SHARE_MODES[0])
        st.button("Save sharing", on_click=save_sharing_cb, args=(current,))
    else:
        st.caption(f"Members: {', '.join(here['members']) or 'none'}. The owner or an admin can change this.")
        shared, with_findings = cases.sharing_of(case_config.data)
        if shared:
            st.caption(f"Evidence shared with {'everyone' if shared == [cases.EVERYONE] else ', '.join(shared)}"
                       f"{' (with findings)' if with_findings else ''}.")
    if st.session_state.get("ac_message"):
        st.caption(st.session_state.ac_message)


# ==========================================
# Sidebar: which case, and what waits for you
# ==========================================
action = None
with st.sidebar:
    st.title("🕵️ DFIR Copilot")
    account_box()
    llm_box()

    st.divider()
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
    if st.button("🧹 New conversation", help="Clears this case's chat and the agent's memory of it. "
                                          "Collected data and findings stay."):
        conversation.clear(cases.current_id(), user=USER)
        open_case_chat()
        st.rerun()
    st.caption(f"LLM tokens this session: "
               f"{st.session_state.usage.session_input + st.session_state.usage.session_output:,}")
    problems = config_check.case_problems(case_config)
    if USER is None or auth.is_admin(USER):
        problems += [f"server.yaml: {p}" for p in config_check.server_problems()]
    if problems:
        st.warning("**Settings problems** (ignored until fixed):\n" + "\n".join(f"- {citations.md_literal(p)}" for p in problems))

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
            if c1.button("Approve", key=f"approve-{req['id']}", on_click=to_chat, disabled=bool(running)):
                action = ("approve", req)
            if c2.button("Deny", key=f"deny-{req['id']}", on_click=to_chat, disabled=bool(running)):
                action = ("deny", req)
        if len(pending_here()) > 1 and st.button("✅ Approve all", key="approve-all", type="primary", on_click=to_chat,
                                                 disabled=bool(running)):
            action = ("approve_all", None)
        st.checkbox("Continue the agent once all are decided", value=True, key="auto_continue",
                    help="Otherwise ask the copilot to continue yourself.")

    st.divider()
    knowledge_panel()

# ==========================================
# Main area: the case at a glance, then one tab per job
# ==========================================
stats = case_db.get_stats()
active = case_db.get_findings()
notes = dossier.latest()
case_header(stats, active, notes)
hint = cases.legacy_data_hint()
if hint:
    st.warning(hint)
chat_tab, findings_tab, data_tab, report_tab, case_tab = st.tabs(TABS, key="main_tab")
with findings_tab:
    action = findings_view(stats, active, notes) or action
with data_tab:
    action = data_view(stats) or action
with report_tab:
    action = report_view() or action
with case_tab:
    case_view(case_rows, current)

# Typed anywhere (the box stays at the bottom of every tab); answered in the Chat tab. While this
# investigator's job runs, the box waits: their conversation has one writer at a time.
prompt = st.chat_input("Ask the copilot to investigate... (/help for commands)", on_submit=to_chat,
                       disabled=bool(running))

with chat_tab:
    for i, msg in enumerate(st.session_state.messages):
        render_message(msg, i)
    if not st.session_state.messages and stats["total_records"] and not prompt and action is None:
        st.caption("Ask about this case in your own words: how they got in, what ran, what was taken, what a "
                   "record means. " + ("Answers start from the case dossier and" if notes else "Answers start from")
                   + " the leads computed from the data, and cite the records they rest on.")

    # Work this page started, or another page of the same investigator, or this page before a reload: follow it.
    if running:
        follow(running)

    # Work a stopped server was doing: continue it (from the saved conversation) or let it go.
    stopped = jobs.problem(USER)
    if stopped and action is None and not prompt:
        with st.container(border=True):
            st.markdown(f"**⚠️ {jobs.NAMES.get(stopped['kind'], 'Some work')} did not finish:** the server stopped "
                        f"while it ran.")
            c1, c2 = st.columns([2, 3])
            if c1.button("↻ Continue", type="primary", key="job_retry"):
                action = ("retry", stopped["job_id"])
            if c2.button("Dismiss", key="job_dismiss"):
                jobs.dismiss(stopped["job_id"])
                st.rerun()
            st.caption("It goes on from the saved conversation; collections it had started are reused, not run again.")

    # First visit to an empty case: offer the triage collection (the CLI asks the same question).
    if (not case_db.get_collections() and not st.session_state.triage_dismissed and action is None and not prompt
            and (not case_config.client_id_error or case_config.memory_image)):
        with st.container(border=True):
            disk = not case_config.client_id_error
            sources = (["the disk image (Velociraptor)"] if disk else []) + \
                      ([f"the memory image `{case_config.memory_image}` (Volatility)"] if case_config.memory_image else [])
            st.markdown(f"**No data collected for this case yet.** Run the initial triage of {' and '.join(sources)}? "
                        f"It needs no LLM.")
            investigate = investigate_choice("first_investigate")
            c1, c2 = st.columns([2, 3])
            p = f"tri_{cases.current_id()}_"          # the same choice as the triage panel
            label = ("Run triage (disk + memory)" if disk and case_config.memory_image else
                     "Run triage" if disk else "Run memory triage")
            if c1.button(label, type="primary", key="first_triage"):
                try:
                    plan = picked_triage(p) if disk else None
                except ValueError:
                    plan = None                        # unusable edits: the case's saved list
                action = ("triage", (investigate, plan, picked_memory(p) if case_config.memory_image else None, disk))
            if c2.button("Skip"):
                st.session_state.triage_dismissed = True
                st.rerun()
            st.caption("📥 Evidence & data → Triage runs the disk or memory part on its own, any time.")

    # Data but no dossier: offer the investigation, as an option (questions work without it).
    elif (case_db.get_collections() and not notes and action is None and not prompt
            and "llm_with_tools" in st.session_state and st.session_state.get("dossier_dismissed") != cases.current_id()):
        with st.container(border=True):
            steps, tokens = dossier.budget()
            st.markdown("**No case dossier yet.** Investigate the whole case now? The agent reads everything collected "
                        "and writes the case's timeline, findings, hypotheses and gaps; every question then starts "
                        "from it, so answers agree and cost less.")
            st.caption(f"Optional: one longer agent turn, up to {steps} steps / {tokens:,} tokens. You can also just ask "
                       f"questions, or run it later from 🚩 Findings & dossier or with /investigate.")
            c1, c2 = st.columns([2, 3])
            if c1.button("🔎 Investigate now", type="primary", key="investigate_card"):
                action = ("investigate", None)
            if c2.button("Not now", key="dossier_not_now"):
                st.session_state.dossier_dismissed = cases.current_id()
                st.rerun()

    # Everything below runs as a job (copilot/jobs.py) that this page follows; follow() reruns the page.
    if action:
        kind, arg = action
        if kind == "triage":
            st.session_state.triage_dismissed = True
            investigate, plan, plugins, disk = (*arg, None, True)[:4] if len(arg) == 2 else arg   # panel: disk only
            follow(start("triage", {"investigate": investigate, "plan": plan, "plugins": plugins, "disk": disk}))
        elif kind == "memory_triage":
            st.session_state.triage_dismissed = True
            follow(start("triage", {"investigate": arg[0], "plugins": arg[1], "disk": False}))
        elif kind == "investigate":
            follow(start("investigate"))
        elif kind == "ask":
            follow(start("ask", {"text": arg}), question=arg)
        elif kind == "retry":
            follow(start("", retry=arg))
        elif kind in ("approve", "deny", "approve_all"):
            # Once nothing waits any more, the agent goes on with the results (no "continue" needed).
            decisions = [[r["id"], kind != "deny"] for r in (pending_here() if kind == "approve_all" else [arg])]
            follow(start("decide", {"decisions": decisions, "auto_continue": st.session_state.get("auto_continue", True)}))

    if prompt:
        investigate = prompt.strip().lower() == commands.INVESTIGATE      # uses the LLM: not a free command
        reply = None if investigate else commands.handle(prompt)
        if investigate:
            follow(start("investigate", {"command": prompt}), question=prompt)
        elif reply is not None:
            conversation.append(st.session_state.case_id, {"role": "user", "content": prompt},
                                {"role": "assistant", "content": reply}, user=USER)
            after_possible_switch()
            st.rerun()
        else:
            follow(start("ask", {"text": prompt}), question=prompt)
