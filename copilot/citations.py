"""
What an answer cites, resolved from the case database for the investigator.

The agent cites records by evidence ID (16 hex characters, e.g. e21c3dce5c1eeb3d) and
findings by finding ID (e.g. 60ad0e42-05d). On their own these mean nothing to a reader,
so the UIs list each one under the answer: time, source and what the record says. This
is a database lookup, so it costs no LLM tokens. Only IDs that exist in the case count.
"""
import re

from copilot.report import Clock

EVIDENCE_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{16}(?![0-9A-Za-z])")
FINDING_RE = re.compile(r"(?<![0-9A-Za-z-])[0-9a-f]{8}-[0-9a-f]{3}(?![0-9A-Za-z])")
MAX_CITED = 100
_MD_PUNCT = re.compile(r"([!-/:-@\[-`{-~])")          # every ASCII punctuation character
_CODE = re.compile(r"(```.*?```|`[^`\n]*`)", re.S)


_AUTOLINK = re.compile(r"(?i)(\b(?:https?|ftp)):(?=//)|\b(www)(?=\.)")
# Evidence IDs a model may have copied wrongly: 12-20 hex characters on their own.
_ID_LIKE = re.compile(r"(?<![0-9A-Za-z-])[0-9a-f]{12,20}(?![0-9A-Za-z-])")


def _distance(a: str, b: str, limit: int = 2) -> int:
    """Edit distance (insert, delete, change, swap neighbours), or limit + 1 once it is exceeded."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def repair_ids(text: str, seen: set, db) -> tuple:
    """
    Fixes evidence IDs the model garbled while copying (a swapped, changed or dropped character):
    an ID that is not in the case but is within 2 edits of exactly one ID the agent saw in its
    tool results (and that exists) is replaced by it. Returns (text, [(wrong, right)]).
    """
    if not text or not seen:
        return text, []
    fixes = {}
    for token in dict.fromkeys(_ID_LIKE.findall(text)):
        if len(token) == 16 and db.get_event_detail(token):
            continue
        matches = [s for s in seen if _distance(token, s) <= 2]
        if len(matches) == 1 and db.get_event_detail(matches[0]):
            fixes[token] = matches[0]
    for wrong, right in fixes.items():
        text = re.sub(r"(?<![0-9A-Za-z-])" + wrong + r"(?![0-9A-Za-z-])", right, text)
    return text, list(fixes.items())


def md_literal(text) -> str:
    """
    Text that Markdown shows exactly as it is: evidence is attacker-written, so it must not
    become links, images, formatting or math ($...$). Every ASCII punctuation character is
    backslash-escaped (CommonMark drops the backslash when rendering), and a zero-width space
    after "http:" / "www" stops URLs in it from becoming clickable links.
    """
    text = " ".join(str(text if text is not None else "").split())
    text = _AUTOLINK.sub(lambda m: f"{m.group(1)}:\u200b" if m.group(1) else f"{m.group(2)}\u200b", text)
    return _MD_PUNCT.sub(r"\\\1", text)


_IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")


def answer_markdown(markdown: str) -> str:
    """
    An agent answer, safe to render: answers quote evidence, which is attacker-written.
    Outside code spans, $ stays a dollar sign (PowerShell $env:windir, not math) and images are
    removed (a remote image would make the browser contact that server).
    """
    def clean(part):
        return _IMAGE.sub(lambda m: f"[image removed{': ' + m.group(1) if m.group(1) else ''}]",
                          part).replace("$", "\\$")

    parts = _CODE.split(markdown or "")
    return "".join(part if i % 2 else clean(part) for i, part in enumerate(parts))


def cited(text: str, db, config) -> dict:
    """{"evidence": [...], "findings": [...]} for the IDs in text that exist in the case database."""
    text = text or ""
    clock = Clock(config.clock_offset_minutes)
    evidence = []
    for evidence_id in list(dict.fromkeys(EVIDENCE_RE.findall(text)))[:MAX_CITED]:
        row = db.conn.execute("SELECT evidence_id, source, description, first_seen FROM records "
                              "WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not row:
            continue
        item = {"Evidence": row["evidence_id"], "Time (UTC)": clock.corrected(row["first_seen"])}
        if clock.skewed:
            item["Recorded"] = clock.recorded(row["first_seen"])
        item.update({"Source": row["source"], "What it shows": row["description"]})
        evidence.append(item)
    findings = []
    for finding_id in list(dict.fromkeys(FINDING_RE.findall(text)))[:MAX_CITED]:
        row = db.conn.execute("SELECT finding_id, title, confidence, COALESCE(status, 'active') AS status "
                              "FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
        if row:
            findings.append({"Finding": row["finding_id"], "Title": row["title"],
                             "Confidence": row["confidence"] or "", "Status": row["status"]})
    return {"evidence": evidence, "findings": findings}


def summary(found: dict) -> str:
    parts = []
    if found["evidence"]:
        parts.append(f"{len(found['evidence'])} evidence record{'s' if len(found['evidence']) != 1 else ''}")
    if found["findings"]:
        parts.append(f"{len(found['findings'])} finding{'s' if len(found['findings']) != 1 else ''}")
    return " and ".join(parts)


def as_text(found: dict, width: int = 110) -> str:
    """Plain-text list for the CLI."""
    lines = []
    for f in found["findings"]:
        lines.append(f"  finding {f['Finding']}  [{f['Confidence'] or '?'}] {f['Title']}"
                     + ("" if f["Status"] == "active" else f" ({f['Status']})"))
    for e in found["evidence"]:
        when = e["Time (UTC)"] + (f" (rec {e['Recorded']})" if "Recorded" in e else "")
        lines.append(f"  {e['Evidence']}  {when}  {e['Source']}\n      {e['What it shows'][:width]}")
    return "\n".join(lines)


# ---------------------------------------------------------------- time check
_T = r"(\d{2}:\d{2}:\d{2})(?:\.\d+)?"
_UTC_TIMES = re.compile(_T + r"(?:\s*(?:[–—-]|to)\s*" + _T + r")?\s*UTC")
_ISO_UTC = re.compile(r"(?<![\d:])" + _T + r"Z(?![0-9A-Za-z])")        # 2024-02-05T23:28:30Z, 20:46:53.2285Z
_RECORDED_TIMES = re.compile(r"recorded\s+" + _T + r"(?:\s*(?:[–—-]|to)\s*" + _T + r")?")
_IN_FIELDS = re.compile(r"(?<![\d:])((?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)")


def _seconds(hms: str) -> int:
    h, m, s = (int(x) for x in hms.split(":"))
    return h * 3600 + m * 60 + s


def time_mismatches(text: str, db, offset_minutes: int = 0, tolerance: int = 2) -> list:
    """
    Times in a text that none of the records cited next to them holds (no LLM): a model that shifted
    a time by hand, or copied the wrong one, shows up here. Per line, every time given as recorded
    (or, without a clock offset, as UTC; with one, a UTC time without its recorded twin is shifted
    back) must be within `tolerance` seconds of a timestamp of one of the line's cited records, or of a
    time written in one of their fields (a task's trigger, a key's last write: the record holds it).
    Lines citing nothing, or only records without timestamps, are not checked.
    Returns [{"line", "time", "cited": {evidence_id: [recorded times]}}].
    """
    out = []
    for line in (text or "").splitlines():
        ids = list(dict.fromkeys(EVIDENCE_RE.findall(line)))
        if not ids:
            continue
        recorded = [t for m in _RECORDED_TIMES.finditer(line) for t in m.groups() if t]
        if not recorded:
            utc = [t for m in _UTC_TIMES.finditer(line) for t in m.groups() if t]
            utc += [m.group(1) for m in _ISO_UTC.finditer(line)]
            recorded = [f"{(_seconds(t) + offset_minutes * 60) % 86400 // 3600:02d}:"
                        f"{(_seconds(t) + offset_minutes * 60) % 3600 // 60:02d}:"
                        f"{(_seconds(t) + offset_minutes * 60) % 60:02d}" for t in utc]
        if not recorded:
            continue
        cited = {}
        for evidence_id in ids:
            rows = db.conn.execute("SELECT timestamp_utc FROM timeline WHERE evidence_id = ?", (evidence_id,)).fetchall()
            times = [str(r[0])[11:19] for r in rows if r[0] and len(str(r[0])) >= 19]
            if times:
                cited[evidence_id] = times
        if not cited:
            continue
        held = {_seconds(t) for times in cited.values() for t in times}
        for evidence_id in cited:
            raw = db.conn.execute("SELECT raw_data FROM records WHERE evidence_id = ?", (evidence_id,)).fetchone()
            held.update(_seconds(t) for t in _IN_FIELDS.findall(str(raw[0] if raw else "")))
        for t in dict.fromkeys(recorded):
            s = _seconds(t)
            if not any(min(abs(s - h), 86400 - abs(s - h)) <= tolerance for h in held):
                out.append({"line": line.strip()[:160], "time": t,
                            "cited": {k: sorted(set(v))[:4] for k, v in cited.items()}})
    return out


def time_check_note(mismatches: list) -> str:
    """The mismatches as a section to append to the text they were found in ("" when there are none)."""
    if not mismatches:
        return ""
    lines = [f"- recorded {m['time']} is not a time of the records cited with it ("
             + "; ".join(f"`{k}`: {', '.join(v)}" for k, v in m["cited"].items())
             + f"): \"{m['line'][:100]}\"" for m in mismatches[:20]]
    return ("\n\n## Time check (automatic, no model)\nThese times are not held by the records cited on the same line. "
            "Check each before quoting it: it may belong to another record, or be shifted:\n" + "\n".join(lines))
