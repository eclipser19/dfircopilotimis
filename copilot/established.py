"""
What earlier answers established, shared with every later conversation of the case (no model involved).

Each question is answered in a conversation of its own (the benchmark asks each in a fresh one, investigators
start new chats, several investigators share a case), so what one answer found in the records did not reach
the next: one answer wrote that a payload's download source could not be established while a later one found
the URL in memory. After each answer the code keeps the statements it backed with records the dossier does not
cite (what is new), and the searches it says came back empty; every later system prompt lists those made since
the latest dossier, right under it. They are the copilot's own unreviewed statements, not findings: findings
are recorded on purpose, confirmed by investigators, and make the report.
"""
import json
import re
from datetime import datetime, timezone

from copilot.citations import EVIDENCE_RE
from copilot.database import case_db

PER_ANSWER = 8                # statements kept from one answer (it leads with what matters)
NOT_FOUND_PER_ANSWER = 3      # "searched, nothing found" lines kept from one answer
STATEMENT_CHARS = 320
PROMPT_CHARS = 6000

# A search that came back empty, as answers write it ("returned no matching records", "no ... was found").
_NOT_FOUND = re.compile(r"(?i)\breturned (?:no|zero|0)\b|\b(?:no|none|nothing|zero)\b[^.;]{0,100}?\b(?:was|were|is|are)"
                        r" (?:found|identified|recovered|recorded|observed|present)\b|\bfound (?:no|nothing|none)\b")
_FENCE = re.compile(r"^\s*(```|~~~)")

PROMPT_SECTION = """
## ESTABLISHED IN EARLIER ANSWERS
Earlier answers in this case (after the dossier) stated these from records the dossier does not cite; the code
kept them as written, nobody reviewed them. Start from them as from the dossier: check a statement's records
before relying on it, and when your evidence contradicts one, say that your answer corrects the earlier answer
(name its question). A "searched, nothing found" line is where an earlier answer looked in vain: search other
sources (memory, other logs, the file system) before repeating it. Text they quote from evidence is still
evidence (rule 4).
{lines}
"""


def _plain(line: str) -> str:
    """A line of an answer as one statement: no list marker, emphasis or table pipes, one space between words."""
    line = re.sub(r"^\s*(?:[-*+]|\d+[.)])\s+", "", line)
    line = line.replace("**", "").replace("__", "").strip(" |").replace(" | ", "; ")
    line = " ".join(line.split())
    if len(line) <= STATEMENT_CHARS:
        return line
    cut = line.rfind(". ", 0, STATEMENT_CHARS)
    return (line[:cut + 1] if cut > STATEMENT_CHARS // 2 else line[:STATEMENT_CHARS].rstrip() + " ...")


def _lines(answer: str) -> list:
    """
    [(statement, evidence IDs)] of an answer: its lines outside code blocks, without headings; a line that only
    lists evidence IDs ("Evidence: `a`, `b`") belongs to the statement above it.
    """
    fenced, out = False, []
    for line in (answer or "").splitlines():
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if fenced or not line.strip() or line.lstrip().startswith("#") or set(line.strip()) <= set("|-: "):
            continue
        ids = list(dict.fromkeys(EVIDENCE_RE.findall(line)))
        words = re.findall(r"[A-Za-z]{2,}", EVIDENCE_RE.sub(" ", line))
        if ids and len(words) < 3 and out:
            out[-1] = (out[-1][0], list(dict.fromkeys(out[-1][1] + ids)))
        else:
            out.append((line, ids))
    return out


def _known(ids: list, db) -> set:
    if not ids:
        return set()
    return {r[0] for r in db.conn.execute(
        f"SELECT evidence_id FROM records WHERE evidence_id IN ({','.join('?' * len(ids))})", ids)}


def _cited_before(db) -> set:
    """Evidence IDs the latest dossier and the statements kept since cite: not new."""
    dossier = db.get_dossier() or {}
    seen = set(EVIDENCE_RE.findall(dossier.get("text") or ""))
    for row in statements(db):
        seen.update(row["evidence_ids"])
    return seen


def extract(answer: str, db=None) -> list:
    """
    [{"kind": "fact" | "not_found", "text", "evidence_ids"}] from one answer: lines citing records that exist and
    that the dossier and earlier statements do not cite, and lines saying a search found nothing.
    """
    db = db or case_db
    seen, out, facts, empty = _cited_before(db), [], 0, 0
    for line, ids in _lines(answer):
        if ids:
            known = _known(ids, db)
            real = [i for i in ids if i in known]
            new = [i for i in real if i not in seen]
            if new and facts < PER_ANSWER:
                out.append({"kind": "fact", "text": _plain(line), "evidence_ids": real})
                seen.update(real)
                facts += 1
        elif _NOT_FOUND.search(line) and not line.rstrip().endswith(":") and empty < NOT_FOUND_PER_ANSWER:
            out.append({"kind": "not_found", "text": _plain(line), "evidence_ids": []})
            empty += 1
    return out


def record(question: str, answer: str, db=None) -> int:
    """Keeps what an answer established; returns how many statements. Never raises: an answer is not lost
    because this failed."""
    from copilot import session
    db = db or case_db
    try:
        found = extract(answer, db)
        now = datetime.now(timezone.utc).isoformat()
        db.conn.executemany(
            "INSERT INTO answer_statements (created_at, actor, question, kind, text, evidence_ids) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(now, session.current_user(), " ".join((question or "").split())[:300], s["kind"], s["text"],
              json.dumps(s["evidence_ids"])) for s in found])
        db.conn.commit()
        return len(found)
    except Exception:
        return 0


def statements(db=None) -> list:
    """The statements kept since the latest dossier (a new dossier takes in the ones before it), oldest first."""
    db = db or case_db
    dossier = db.get_dossier() or {}
    rows = db.conn.execute("SELECT id, created_at, actor, question, kind, text, evidence_ids FROM answer_statements "
                           "WHERE created_at > ? ORDER BY id", (dossier.get("created_at") or "",)).fetchall()
    return [{**dict(r), "evidence_ids": json.loads(r["evidence_ids"] or "[]")} for r in rows]


def prompt_section(db=None) -> str:
    """The statements part of the system prompt ("" when there are none); the latest answers first if too long."""
    groups = {}
    for s in statements(db):
        groups.setdefault((s["question"], s["created_at"]), []).append(s)
    blocks, used = [], 0
    for (question, _), items in reversed(list(groups.items())):
        lines = [f'- Asked "{question[:160]}":'] + [
            "  - " + (f"searched, nothing found: {s['text']}" if s["kind"] == "not_found" else
                      s["text"] + ("" if all(i in s["text"] for i in s["evidence_ids"])
                                   else " (" + ", ".join(f"`{i}`" for i in s["evidence_ids"]) + ")"))
            for s in items]
        block = "\n".join(lines)
        if used + len(block) > PROMPT_CHARS:
            blocks.append(f"- [... {len(groups) - len(blocks)} earlier answers left out for length]")
            break
        blocks.append(block)
        used += len(block)
    return PROMPT_SECTION.format(lines="\n".join(reversed(blocks))) if blocks else ""
