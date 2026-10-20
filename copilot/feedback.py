"""
Investigators teach the copilot as they use it.

- **Notes** (per case): facts and corrections an investigator gives, in the app's Findings & dossier
  tab, under an answer (👎 + what is right) or with `/note <text>`. Every conversation and
  investigation of the case gets them in its system prompt, above the dossier: the agent builds on
  them and says so when evidence contradicts one. They can be withdrawn.
- **Ratings** of answers and dossiers (👍 right / 👎 wrong, with the correction), kept with the
  question and the answer they rate.
- **Confirmed findings**: an investigator checked a finding's records; the agent treats it as
  established and the report names who confirmed it.
- **Lessons**: a correction that holds for every case (how to read an artifact, not a case fact)
  can be proposed as a lesson (copilot/lessons.py), which an admin accepts.
- **Export** for whoever improves the copilot: every note, rating and confirmed finding of every
  case, with the question and answer, as JSON lines (new benchmark questions, prompt fixes, tuning):

    python -m copilot.feedback list
    python -m copilot.feedback export [--out feedback_exports/feedback.jsonl]

The export holds answers that quote evidence: it stays on the server (git-ignored folder).
"""
import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone

from copilot import session
from copilot.database import case_db

NOTES_CHARS = 4000          # the most of a case's notes that goes into each system prompt
EXPORT_DIR = "feedback_exports"

PROMPT_SECTION = """
## INVESTIGATOR NOTES
What the investigators of this case have established or corrected, newest first. These outrank the
dossier and your earlier answers: build on them, and if evidence you find contradicts one, say so and
cite it instead of overriding it silently.
<notes>
{notes}
</notes>
"""


class FeedbackError(Exception):
    """The feedback was not saved; the message is for the investigator."""


def notes(db=None) -> list:
    """The case's active notes and corrections (feedback with a comment), newest first."""
    rows = (db or case_db).get_feedback()
    return [r for r in reversed(rows) if (r.get("comment") or "").strip()]


def stamp(db=None) -> tuple:
    """Changes whenever the notes do (the app refreshes the system prompt on it)."""
    rows = (db or case_db).get_feedback(include_withdrawn=True)
    return (len(rows), sum(r["active"] for r in rows))


def prompt_section(db=None) -> str:
    """The notes part of the system prompt ("" when the case has none)."""
    lines, used = [], 0
    for r in notes(db):
        about = f' (correcting the answer to: "{r["question"][:120]}")' if r.get("rating", 0) < 0 and r.get("question") else ""
        line = (f"- [note {r['feedback_id']}, {r.get('actor') or 'investigator'}, {str(r['created_at'])[:16].replace('T', ' ')}"
                f" UTC] {' '.join(r['comment'].split())}{about}")
        if used + len(line) > NOTES_CHARS:
            lines.append(f"- [... {len(notes(db)) - len(lines)} older notes left out for length]")
            break
        lines.append(line)
        used += len(line)
    return PROMPT_SECTION.format(notes="\n".join(lines)) if lines else ""


def _changed():
    """The active conversation's system prompt must be rebuilt (the UIs check consume_settings_change)."""
    current = session.current()
    current.settings_changed = True


def add_note(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise FeedbackError("Write the fact or correction the copilot should take as given.")
    entry = case_db.add_feedback("note", 0, text)
    case_db.log_query("feedback", f"note {entry['feedback_id']}: {text[:300]}", 0)
    _changed()
    return entry


def rate(kind: str, rating: int, comment: str = "", question: str = "", answer: str = "") -> dict:
    """A rating of an answer or dossier: 1 right, -1 wrong (a correction is then required)."""
    comment = (comment or "").strip()
    if rating < 0 and not comment:
        raise FeedbackError("Say what is wrong or what is right: that is what the copilot learns from.")
    entry = case_db.add_feedback(kind, 1 if rating > 0 else -1, comment, question, answer)
    case_db.log_query("feedback", f"{kind} rated {'right' if rating > 0 else 'wrong'} ({entry['feedback_id']})"
                                  + (f": {comment[:300]}" if comment else ""), 0)
    if comment:
        _changed()
    return entry


def withdraw(feedback_id: int) -> bool:
    done = case_db.withdraw_feedback(feedback_id)
    if done:
        case_db.log_query("feedback", f"note {feedback_id} withdrawn", 0)
        _changed()
    return done


def confirm_finding(finding_id: str) -> dict:
    found = case_db.confirm_finding(finding_id, session.current_user())
    if not found:
        raise FeedbackError(f"No unique finding '{finding_id}'.")
    case_db.log_query("feedback", f"finding {found['finding_id']} confirmed: {found['title'][:200]}", 0)
    return found


# ---------------------------------------------------------------- server-side: all cases
def _case_databases():
    """(case_id, sqlite connection) of every case with data, read directly (no migrations, no locks held)."""
    from copilot import cases
    from copilot.database import data_dir_for
    for case_id in cases._all_ids():
        db_file = os.path.join(data_dir_for(cases._case_file(case_id)), "case.db")
        if os.path.isfile(db_file):
            conn = sqlite3.connect(db_file, timeout=60)
            conn.row_factory = sqlite3.Row
            try:
                yield case_id, conn
            finally:
                conn.close()


def _rows(conn, query: str) -> list:
    try:
        return [dict(r) for r in conn.execute(query)]
    except sqlite3.OperationalError:          # a database from before feedback existed
        return []


def collect_all() -> list:
    """Every note, rating and confirmed finding of every case (for list and export)."""
    out = []
    for case_id, conn in _case_databases():
        for r in _rows(conn, "SELECT * FROM feedback ORDER BY feedback_id"):
            out.append({"case": case_id, "type": r["kind"], **{k: r[k] for k in
                        ("feedback_id", "created_at", "actor", "rating", "question", "answer", "comment", "active")}})
        for r in _rows(conn, "SELECT finding_id, title, description, evidence_ids, confidence, confirmed_by "
                             "FROM findings WHERE confirmed_by IS NOT NULL AND COALESCE(status, 'active') = 'active'"):
            out.append({"case": case_id, "type": "confirmed_finding", **r})
    return out


def export(out_path: str = None, log=print) -> str:
    items = collect_all()
    out_path = out_path or os.path.join(EXPORT_DIR, f"feedback-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.jsonl")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
    log(f"[*] {len(items)} items written to {out_path} (answers quote evidence: keep the file on the server)")
    return out_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m copilot.feedback", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="counts per case: notes, right/wrong ratings, confirmed findings")
    e = sub.add_parser("export", help="everything investigators said, as JSON lines")
    e.add_argument("--out", help=f"output file (default: {EXPORT_DIR}/feedback-<time>.jsonl)")
    args = parser.parse_args(argv)
    if args.command == "export":
        export(args.out)
        return 0
    per_case = {}
    for item in collect_all():
        c = per_case.setdefault(item["case"], {"notes": 0, "right": 0, "wrong": 0, "confirmed findings": 0})
        if item["type"] == "confirmed_finding":
            c["confirmed findings"] += 1
        elif item.get("rating", 0) > 0:
            c["right"] += 1
        elif item.get("rating", 0) < 0:
            c["wrong"] += 1
        elif item.get("active"):
            c["notes"] += 1
    for case_id, c in sorted(per_case.items()):
        print(f"{case_id}: " + ", ".join(f"{v} {k}" for k, v in c.items()))
    if not per_case:
        print("No feedback yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
