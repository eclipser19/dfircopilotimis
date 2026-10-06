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


def default_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(case_db.db_path), "outputs"))


def output_dir() -> str:
    """Absolute path (on Windows '/uploads' means C:\\uploads, so show what it really is)."""
    path = (os.environ.get("DFIR_OUTPUT_DIR")
            or str((case_config.data.get("output", {}) or {}).get("dir", "") or "")
            or default_dir())
    path = os.path.abspath(path)
    os.makedirs(path, exist_ok=True)
    return path


def locate(entry: dict) -> str:
    """
    Current location of a registered file. If it was moved (e.g. the output folder changed or
    the case folder was reorganised), look for the same file name in the case's output folders
    and remember the new location. Returns "" if it can't be found.
    """
    path = entry["path"]
    if os.path.isfile(path):
        return path
    name = os.path.basename(path.replace("\\", "/"))
    for folder in dict.fromkeys([output_dir(), default_dir()]):
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate):
            if entry.get("output_id") is not None:
                case_db.conn.execute("UPDATE outputs SET path = ? WHERE output_id = ?",
                                     (candidate, entry["output_id"]))
                case_db.conn.commit()
            entry["path"] = candidate
            return candidate
    return ""


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
