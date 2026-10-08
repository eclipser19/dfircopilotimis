"""
Per-case chat persistence.

Each case's database keeps its conversation: the messages shown in the UI and the agent's
own message history (tool calls included, so the agent remembers what it did). Saved after
every exchange and restored when the case is opened again, also after an app restart. The
system prompt is never stored: it is rebuilt from the case settings on load.

With sign-in, each investigator has their own conversation in a shared case. A user who has
none yet gets the case's conversation from before sign-in (if any), so nothing is lost when
accounts are introduced.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

from langchain_core.messages import SystemMessage, messages_from_dict, messages_to_dict

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
    return ("ui", "agent") if not user else (f"ui@{user}", f"agent@{user}")


def save(case_id: str, ui_messages: list = None, agent_history: list = None, user: str = None):
    ui_key, agent_key = _keys(user)
    conn, own = _connect(case_id)
    try:
        conn.execute(SCHEMA)
        now = datetime.now(timezone.utc).isoformat()
        if ui_messages is not None:
            conn.execute("INSERT OR REPLACE INTO conversation VALUES (?, ?, ?)",
                         (ui_key, json.dumps(ui_messages, default=str), now))
        if agent_history is not None:
            kept = [m for m in agent_history if not isinstance(m, SystemMessage)]
            conn.execute("INSERT OR REPLACE INTO conversation VALUES (?, ?, ?)",
                         (agent_key, json.dumps(messages_to_dict(kept), default=str), now))
        conn.commit()
    finally:
        if own:
            conn.close()


def load(case_id: str, system_prompt: str, user: str = None) -> tuple:
    """(ui_messages, agent_history): agent history starts with a fresh system prompt."""
    conn, own = _connect(case_id)
    try:
        conn.execute(SCHEMA)
        rows = dict(conn.execute("SELECT key, value FROM conversation").fetchall())
    finally:
        if own:
            conn.close()
    ui_key, agent_key = _keys(user)
    if ui_key not in rows and agent_key not in rows:
        ui_key, agent_key = _keys(None)          # this user's first visit: the pre-sign-in chat, if any
    ui = json.loads(rows[ui_key]) if rows.get(ui_key) else []
    try:
        agent = messages_from_dict(json.loads(rows[agent_key])) if rows.get(agent_key) else []
    except (ValueError, KeyError, TypeError):
        agent = []
    from copilot.agent import repair_history
    return ui, repair_history([SystemMessage(content=system_prompt)] + agent)


def clear(case_id: str, user: str = None):
    save(case_id, ui_messages=[], agent_history=[], user=user)
