"""
Builds the DFIR report. Everything except the narrative (executive summary,
correlation analysis, recommendations) is computed from the case database, so
times, evidence and artifact explanations can't be invented by the LLM.
"""
import json
from datetime import datetime, timedelta, timezone
from itertools import combinations

from jinja2 import Environment

from copilot.knowledge import artifact_info
from copilot.normalize import event_type_for, normalize_row, parse_timestamp
from copilot.report_template import REPORT_TEMPLATE

MAX_TIMELINE_ROWS = 200
RELATED_WITHIN_MINUTES = 15
INDICATOR_FIELDS = [("ip", "IP addresses"), ("user", "Accounts"), ("process", "Processes"),
                    ("path", "Files / paths"), ("hash", "Hashes"), ("command_line", "Command lines")]


def md(value, limit: int = None) -> str:
    """Safe for a Markdown table cell: no pipes or line breaks."""
    text = " ".join(str(value if value is not None else "").split()).replace("|", "\\|")
    if limit and len(text) > limit:
        text = text[:limit - 1] + "…"
    return text


class Clock:
    """Converts recorded (host clock) times to true UTC using the case's clock offset."""

    def __init__(self, offset_minutes: int):
        self.offset = timedelta(minutes=offset_minutes)
        self.skewed = bool(offset_minutes)

    def _parse(self, ts):
        return parse_timestamp(ts, "time") if ts else None

    def recorded(self, ts) -> str:
        dt = self._parse(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "—"

    def corrected(self, ts) -> str:
        dt = self._parse(ts)
        return (dt - self.offset).strftime("%Y-%m-%d %H:%M:%S") if dt else "—"


def _evidence(db, evidence_id: str, window: tuple) -> dict:
    rec = db.get_event_detail(evidence_id)
    if not rec:
        return {}
    # Re-describe from the raw row so records ingested by older versions read well too.
    try:
        rec["description"] = normalize_row(json.loads(rec["raw_data"]), rec["source"])["description"]
    except (ValueError, TypeError):
        pass
    stamps = [t for t in rec["timestamps"] if _in_window(t["timestamp_utc"], window)] or rec["timestamps"]
    return {"evidence_id": evidence_id, "source": rec["source"], "description": rec["description"],
            "timestamps": stamps, "first": stamps[0]["timestamp_utc"] if stamps else None,
            "entities": {f: rec.get(f) for f, _ in INDICATOR_FIELDS if rec.get(f)}}


def _in_window(ts: str, window: tuple) -> bool:
    start, end = window
    return (not start or ts >= start) and (not end or ts <= end)


def build_report(db, config, executive_summary: str, recommendations: str, correlations: str = None,
                 now: datetime = None) -> str:
    from copilot.normalize import normalize_bound
    now = now or datetime.now(timezone.utc)
    clock = Clock(config.clock_offset_minutes)
    window = (normalize_bound(config.start_time) if config.has_scope else None,
              normalize_bound(config.end_time) if config.has_scope else None)
    stats = db.get_stats()

    # Findings, each timed by its own evidence (recorded host time), not by what the LLM typed.
    findings = []
    evidence_cache = {}
    for raw in db.get_findings():
        ids = json.loads(raw["evidence_ids"] or "[]")
        items = []
        for eid in ids:
            if eid not in evidence_cache:
                evidence_cache[eid] = _evidence(db, eid, window)
            if evidence_cache[eid]:
                items.append(evidence_cache[eid])
        # The first cited record is the primary one: its time is the finding's time.
        primary = items[0]["first"] if items else None
        findings.append({**raw, "evidence": items, "time": primary})
    findings.sort(key=lambda f: (f["time"] is None, f["time"] or ""))
    for n, f in enumerate(findings, 1):
        f["number"] = n

    # Evidence timeline: every timestamp of every cited record, inside the incident window.
    # Timestamps of the same record within the same second are merged into one row.
    rows = {}
    for f in findings:
        for e in f["evidence"]:
            for t in e["timestamps"]:
                key = (e["evidence_id"], t["timestamp_utc"][:19])
                row = rows.get(key)
                if row is None:
                    row = rows[key] = {"ts": t["timestamp_utc"], "fields": [], "source": e["source"],
                                       "description": e["description"], "evidence_id": e["evidence_id"],
                                       "findings": set()}
                for field in t["timestamp_desc"].split(", "):
                    if field not in row["fields"]:
                        row["fields"].append(field)
                row["findings"].add(f["number"])
    timeline = sorted(rows.values(), key=lambda r: (r["ts"], r["evidence_id"]))
    for r in timeline:
        r["field"] = ", ".join(r["fields"])
    timeline_truncated = len(timeline) > MAX_TIMELINE_ROWS
    timeline = timeline[:MAX_TIMELINE_ROWS]

    # Related findings: shared evidence, or close together in time.
    related = []
    for a, b in combinations(findings, 2):
        shared = {e["evidence_id"] for e in a["evidence"]} & {e["evidence_id"] for e in b["evidence"]}
        reasons = []
        if shared:
            reasons.append(f"share evidence {', '.join(sorted(shared))}")
        if a["time"] and b["time"]:
            gap = abs((parse_timestamp(b["time"], "t") - parse_timestamp(a["time"], "t")).total_seconds()) / 60
            if gap <= RELATED_WITHIN_MINUTES:
                reasons.append(f"{gap:.0f} min apart")
        if reasons:
            related.append({"a": a["number"], "b": b["number"], "reason": "; ".join(reasons)})

    # Indicators seen in cited evidence (not guesses).
    indicators = []
    for field, label in INDICATOR_FIELDS:
        values = {}
        for f in findings:
            for e in f["evidence"]:
                value = e["entities"].get(field)
                if value:
                    values.setdefault(value, set()).add(f["number"])
        if values:
            indicators.append({"label": label, "values": [{"value": v, "findings": sorted(n)}
                                                          for v, n in sorted(values.items())]})

    iocs_searched = []
    if config.has_iocs:
        for ioc_type, values in config.iocs.items():
            for val in (values or []):
                iocs_searched.append({"value": val, "type": ioc_type,
                                      "hits": db.search_events(str(val), limit=1)["total"]})

    # Artifacts: what each collected source is, where it lives, what it proves.
    artifacts = []
    for src in stats["by_source"]:
        src["event_type"] = event_type_for(src["source"])  # current mapping, not the one stored at ingest
        info = artifact_info(src["source"])
        artifacts.append({**src, **info})
    retracted = [f for f in db.get_findings(include_retracted=True) if (f.get("status") or "active") != "active"]

    cur = db.conn.cursor()
    audit_log = [dict(r) for r in cur.execute("SELECT * FROM audit_log ORDER BY timestamp_utc ASC")]
    collections = db.get_collections()
    in_window = None
    if window[0] or window[1]:
        res = db.query_timeline(window[0], window[1], limit=1)
        in_window = res["total"]

    env = Environment(trim_blocks=True, lstrip_blocks=True, autoescape=False)
    env.filters["md"] = md
    env.filters["rec"] = clock.recorded
    env.filters["utc"] = clock.corrected
    return env.from_string(REPORT_TEMPLATE).render(
        case_name=config.case_name, analyst=config.analyst,
        generated_at=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        executive_summary=executive_summary, recommendations=recommendations,
        correlations=correlations,
        has_scope=config.has_scope, start_time=config.start_time, end_time=config.end_time,
        scope_description=config.description,
        clock_skewed=clock.skewed, clock_offset=config.clock_offset_minutes,
        stats=stats, in_window=in_window,
        findings=findings, timeline=timeline, timeline_truncated=timeline_truncated,
        max_timeline=MAX_TIMELINE_ROWS, related=related, related_minutes=RELATED_WITHIN_MINUTES,
        indicators=indicators, iocs_searched=iocs_searched, artifacts=artifacts,
        collections=collections, audit_log=audit_log, retracted=retracted,
    )


def finding_time(db, evidence_ids: list, window: tuple):
    """Recorded time of the primary (first) evidence record, inside the window when possible."""
    for eid in evidence_ids[:1]:
        ev = _evidence(db, str(eid), window)
        if ev and ev["first"]:
            return ev["first"]
    return None
