"""
Per-case chat persistence.

Each case's database keeps its conversation: the messages shown in the UI and the agent's
own message history (tool calls included, so the agent remembers what it did). Saved after
every exchange and restored when the case is opened again, also after an app restart. The
system prompt is never stored: it is rebuilt from the case settings on load.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

from langchain_core.messages import SystemMessage, messages_from_dict, messages_to_dict

SCHEMA = "CREATE TABLE IF NOT EXISTS conversation (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)"


def _connect(case_id: str):
    """The active case's own connection, or a short-lived one to another case's database."""
    from copilot import cases
    if case_id == cases.current_id():
        return cases.case_db.conn, False
    from copilot.database import data_dir_for
    folder = data_dir_for(cases._case_file(case_id))
    os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(os.path.join(folder, "case.db"))
    return conn, True


def save(case_id: str, ui_messages: list = None, agent_history: list = None):
    conn, own = _connect(case_id)
    try:
        conn.execute(SCHEMA)
        now = datetime.now(timezone.utc).isoformat()
        if ui_messages is not None:
            conn.execute("INSERT OR REPLACE INTO conversation VALUES ('ui', ?, ?)",
                         (json.dumps(ui_messages, default=str), now))
        if agent_history is not None:
            kept = [m for m in agent_history if not isinstance(m, SystemMessage)]
            conn.execute("INSERT OR REPLACE INTO conversation VALUES ('agent', ?, ?)",
                         (json.dumps(messages_to_dict(kept), default=str), now))
        conn.commit()
    finally:
        if own:
            conn.close()


def load(case_id: str, system_prompt: str) -> tuple:
    """(ui_messages, agent_history): agent history starts with a fresh system prompt."""
    conn, own = _connect(case_id)
    try:
        conn.execute(SCHEMA)
        rows = dict(conn.execute("SELECT key, value FROM conversation").fetchall())
    finally:
        if own:
            conn.close()
    ui = json.loads(rows["ui"]) if rows.get("ui") else []
    try:
        agent = messages_from_dict(json.loads(rows["agent"])) if rows.get("agent") else []
    except (ValueError, KeyError, TypeError):
        agent = []
    return ui, [SystemMessage(content=system_prompt)] + agent


def clear(case_id: str):
    save(case_id, ui_messages=[], agent_history=[])
