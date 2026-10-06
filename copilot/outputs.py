"""
Files the copilot produces for the investigator (reports, exports, evidence extracts).

They are written to one output directory, configurable for deployments (e.g. a host
folder like /uploads), and registered in the case database so the Streamlit app can
offer each new file as a download in the chat.

Directory: DFIR_OUTPUT_DIR, else case.yaml `output.dir`, else <case dir>/outputs.
"""
import os
import re
from datetime import datetime, timezone

from copilot.case_config import case_config
from copilot.database import case_db


def output_dir() -> str:
    path = (os.environ.get("DFIR_OUTPUT_DIR")
            or str((case_config.data.get("output", {}) or {}).get("dir", "") or "")
            or os.path.join(os.path.dirname(case_db.db_path), "outputs"))
    os.makedirs(path, exist_ok=True)
    return path


def new_path(stem: str, ext: str) -> str:
    """A fresh, safe file path inside the output directory."""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._") or "output"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir(), f"{safe}_{stamp}.{ext.lstrip('.')}")
    n = 1
    while os.path.exists(path):
        path = os.path.join(output_dir(), f"{safe}_{stamp}_{n}.{ext.lstrip('.')}")
        n += 1
    return path


def register(path: str, kind: str, description: str) -> dict:
    """Records a produced file; returns its registry entry."""
    entry = {"path": os.path.abspath(path), "kind": kind, "description": description,
             "created_at": datetime.now(timezone.utc).isoformat(), "size": os.path.getsize(path)}
    case_db.conn.execute(
        "INSERT INTO outputs (path, kind, description, created_at, size) VALUES (?,?,?,?,?)",
        (entry["path"], kind, description, entry["created_at"], entry["size"]))
    case_db.conn.commit()
    return entry


def produced_since(output_id: int) -> list:
    """Files registered after the given output ID (0 = all)."""
    cur = case_db.conn.execute("SELECT * FROM outputs WHERE output_id > ? ORDER BY output_id", (output_id,))
    return [dict(r) for r in cur.fetchall()]


def last_output_id() -> int:
    row = case_db.conn.execute("SELECT COALESCE(MAX(output_id), 0) FROM outputs").fetchone()
    return row[0]
