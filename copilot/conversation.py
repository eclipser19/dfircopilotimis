"""
Per-case chat persistence.

Each case's database keeps its conversation: the messages shown in the UI and the agent's
own message history (tool calls included, so the agent remembers what it did). Saved after
every exchange and restored when the case is opened again, also after an app restart. The
system prompt is never stored: it is rebuilt from the case settings on load.

With sign-in, each investigator has their own conversation in a shared case. A user who has
none yet gets the case's conversation from before sign-in (if any), so nothing is lost when
accounts are introduced.

The web app's background jobs add to the conversation while the page shows it, so changes go
through append / update_message / save_history / begin, one at a time per process. What the
investigator does on the page that the agent should know waits in an inbox (note_for_agent) until
the agent's next turn takes it.
"""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage, messages_from_dict, messages_to_dict

SCHEMA = "CREATE TABLE IF NOT EXISTS conversation (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)"


def _connect(case_id: str):
    """The active case's own connection, or a short-lived one to another case's database."""
    from copilot import cases, session
    if session.current().has_case and case_id == cases.current_id():
        return cases.case_db.conn, False
    from copilot.database import data_dir_for
    folder = data_dir_for(cases._case_file(case_id))
    os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(os.path.join(folder, "case.db"), timeout=60)
    return conn, True


def _keys(user: str = None) -> tuple:
    return ("ui", "agent", "inbox") if not user else (f"ui@{user}", f"agent@{user}", f"inbox@{user}")


# One writer at a time per process: the page and the background jobs (copilot/jobs.py) both add to a
# conversation, and each change reads it, changes it and writes it back.
_lock = threading.RLock()


def _read(conn, user: str = None) -> tuple:
    """(ui, agent message dicts, inbox texts) as stored; a user without a conversation yet gets the one
    from before sign-in."""
    conn.execute(SCHEMA)
    rows = dict(conn.execute("SELECT key, value FROM conversation").fetchall())
    ui_key, agent_key, inbox_key = _keys(user)
    if ui_key not in rows and agent_key not in rows:
        ui_key, agent_key, _ = _keys(None)
    ui = json.loads(rows[ui_key]) if rows.get(ui_key) else []
    agent = json.loads(rows[agent_key]) if rows.get(agent_key) else []
    inbox = json.loads(rows[inbox_key]) if rows.get(inbox_key) else []
    return ui, agent, inbox


def _write(conn, user: str = None, ui: list = None, agent: list = None, inbox: list = None):
    now = datetime.now(timezone.utc).isoformat()
    for key, value in zip(_keys(user), (ui, agent, inbox)):
        if value is not None:
            conn.execute("INSERT OR REPLACE INTO conversation VALUES (?, ?, ?)", (key, json.dumps(value, default=str), now))
    conn.commit()


def _history(system_prompt: str, agent: list, inbox: list) -> list:
    try:
        messages = messages_from_dict(agent)
    except (ValueError, KeyError, TypeError):
        messages = []
    from copilot.agent import repair_history
    return repair_history([SystemMessage(content=system_prompt)] + messages + [HumanMessage(content=t) for t in inbox])


def save(case_id: str, ui_messages: list = None, agent_history: list = None, user: str = None):
    conn, own = _connect(case_id)
    try:
        with _lock:
            conn.execute(SCHEMA)
            agent = None
            if agent_history is not None:
                agent = messages_to_dict([m for m in agent_history if not isinstance(m, SystemMessage)])
            _write(conn, user, ui_messages, agent)
    finally:
        if own:
            conn.close()


def save_history(case_id: str, agent_history: list, user: str = None):
    """The agent's history only (a job's checkpoint after each step)."""
    save(case_id, agent_history=agent_history, user=user)


def load(case_id: str, system_prompt: str, user: str = None) -> tuple:
    """(ui_messages, agent_history): agent history starts with a fresh system prompt and ends with the notes the
    investigator left for the agent since its last turn."""
    conn, own = _connect(case_id)
    try:
        with _lock:
            ui, agent, inbox = _read(conn, user)
    finally:
        if own:
            conn.close()
    return ui, _history(system_prompt, agent, inbox)


def messages(case_id: str, user: str = None) -> list:
    """The messages the chat shows."""
    conn, own = _connect(case_id)
    try:
        with _lock:
            return _read(conn, user)[0]
    finally:
        if own:
            conn.close()


def begin(case_id: str, system_prompt: str, user: str = None) -> tuple:
    """load() for a job that is about to add to the conversation: the investigator's notes move from the inbox
    into the agent's history in the same step, so none is lost or given twice."""
    conn, own = _connect(case_id)
    try:
        with _lock:
            ui, agent, inbox = _read(conn, user)
            history = _history(system_prompt, agent, inbox)
            if inbox:
                _write(conn, user, ui, messages_to_dict(history[1:]), [])
    finally:
        if own:
            conn.close()
    return ui, history


def append(case_id: str, *ui_messages: dict, user: str = None):
    """Adds messages to the chat."""
    conn, own = _connect(case_id)
    try:
        with _lock:
            ui, agent, _ = _read(conn, user)
            _write(conn, user, ui + list(ui_messages), agent)
    finally:
        if own:
            conn.close()


def update_message(case_id: str, index: int, user: str = None, **fields):
    """Changes fields of one chat message (e.g. that it was corrected)."""
    conn, own = _connect(case_id)
    try:
        with _lock:
            ui, agent, _ = _read(conn, user)
            if 0 <= index < len(ui):
                ui[index].update(fields)
                _write(conn, user, ui, agent)
    finally:
        if own:
            conn.close()


def note_for_agent(case_id: str, text: str, user: str = None):
    """Something the investigator did that the agent should know (an import, a confirmed or retracted finding):
    given to the agent at the start of its next turn."""
    conn, own = _connect(case_id)
    try:
        with _lock:
            ui, agent, inbox = _read(conn, user)
            _write(conn, user, ui, agent, inbox + [text])
    finally:
        if own:
            conn.close()


def clear(case_id: str, user: str = None):
    conn, own = _connect(case_id)
    try:
        with _lock:
            conn.execute(SCHEMA)
            _write(conn, user, [], [], [])
    finally:
        if own:
            conn.close()
