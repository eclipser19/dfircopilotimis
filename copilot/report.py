"""
Builds the DFIR report. Everything except the narrative (executive summary,
correlation analysis, recommendations) is computed from the case database, so
times, evidence and artifact explanations can't be invented by the LLM.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from itertools import combinations

from jinja2 import Environment

from copilot.knowledge import artifact_info, event_info, logon_type
from copilot.normalize import flatten
from copilot.normalize import describe, event_type_for, extract_entities, parse_timestamp
from copilot.report_template import REPORT_TEMPLATE

MAX_TIMELINE_ROWS = 200
RELATED_WITHIN_MINUTES = 15
INDICATOR_FIELDS = [("ip", "IP addresses"), ("user", "Accounts"), ("process", "Processes"),
                    ("path", "Files / paths"), ("hash", "Hashes"), ("command_line", "Command lines")]


def md(value) -> str:
    """Safe for a Markdown table cell: pipes escaped, line breaks become spaces. Never shortened."""
    return " ".join(str(value if value is not None else "").split()).replace("|", "\\|")


def fenced(text: str, lang: str = "json") -> str:
    """Code block whose fence is longer than any backtick run inside the text."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"


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
    # Re-describe from the raw row, in full: the database copy is capped for the LLM, the
    # report must not be. This also upgrades records ingested by older versions.
    raw = {}
    try:
        raw = json.loads(rec["raw_data"])
    except (ValueError, TypeError):
        pass
    if isinstance(raw, dict) and raw:
        full_entities = extract_entities(raw, cap=None)
        rec["description"] = describe(raw, full_entities, limit=None)
        rec.update(full_entities)
    stamps = [t for t in rec["timestamps"] if _in_window(t["timestamp_utc"], window)] or rec["timestamps"]
    return {"evidence_id": evidence_id, "source": rec["source"], "description": rec["description"],
            "raw": raw, "all_timestamps": rec["timestamps"], **_event_meaning(raw),
            "timestamps": stamps, "first": stamps[0]["timestamp_utc"] if stamps else None,
            "entities": {f: rec.get(f) for f, _ in INDICATOR_FIELDS if rec.get(f)}}


def _event_meaning(raw) -> dict:
    """Event ID, log channel and their meaning from the knowledge base, for Windows events."""
    if not isinstance(raw, dict):
        return {"event": None, "meaning": ""}
    fields = {}
    for key, value in flatten(raw):
        last = key.rsplit(".", 1)[-1].lower()
        if value in (None, ""):
            continue
        if last == "eventid" or key.lower().endswith("eventid.value"):
            fields.setdefault("id", value)
        elif last == "channel" or key.lower().endswith("provider.name"):
            fields.setdefault("channel", str(value))
        elif last == "logontype":
            fields.setdefault("logon_type", value)
    if "id" not in fields:
        return {"event": None, "meaning": ""}
    info = event_info(fields["id"], fields.get("channel", ""))
    if not info:
        return {"event": None, "meaning": ""}
    meaning = f"{info['id']}: {info['meaning']}"
    if fields.get("logon_type") is not None and logon_type(fields["logon_type"]):
        meaning += f" (LogonType {fields['logon_type']}: {logon_type(fields['logon_type'])})"
    return {"event": info, "meaning": meaning}


# Placeholder values Windows writes when a field doesn't apply; never indicators.
_PLACEHOLDERS = {"-", "--", "null", "none", "n/a", "na", "local", "localhost", "unknown", "%%2313", "0", "::",
                 "::1", "127.0.0.1", "0.0.0.0", "system", "nt authority", "s-1-0-0"}


def is_noise(field: str, value: str) -> bool:
    """Values that are where evidence came from or placeholders, not indicators."""
    import ipaddress
    v = str(value).strip()
    if v.lower() in _PLACEHOLDERS:
        return True
    if field == "ip":
        try:
            ipaddress.ip_address(v.split("%")[0])
        except ValueError:
            return True
    if field == "path":
        low = v.lower().replace("/", "\\")
        # The log file an event came from, or the image's own device path, is the source, not an IOC.
        if low.endswith(".evtx") and "\\winevt\\logs\\" in low:
            return True
    return False


def _in_window(ts: str, window: tuple) -> bool:
    start, end = window
    return (not start or ts >= start) and (not end or ts <= end)


def build_report(db, config, executive_summary: str, recommendations: str, correlations: str = None,
                 now: datetime = None, with_charts: bool = False):
    """
    The report as Markdown. With with_charts=True returns (markdown, charts): the Markdown
    then holds [[chart:name]] lines where report_html.to_html inserts the SVG charts.
    """
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
                                       "description": e["description"], "meaning": e["meaning"],
                                       "evidence_id": e["evidence_id"],
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
                if value and not is_noise(field, value):
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
    cited = {}
    for f in findings:
        for e in f["evidence"]:
            entry = cited.setdefault(e["evidence_id"], {**e, "findings": []})
            entry["findings"].append(f["number"])
    cited = sorted(cited.values(), key=lambda e: (e["first"] is None, e["first"] or "", e["evidence_id"]))
    events_referenced = {}
    for e in cited:
        if e["event"]:
            events_referenced[(e["event"]["id"], e["event"]["channel"])] = e["event"]
    events_referenced = [events_referenced[k] for k in sorted(events_referenced)]
    for e in cited:
        e["raw_json"] = json.dumps(e["raw"], indent=2, ensure_ascii=False, default=str)
    retracted = [f for f in db.get_findings(include_retracted=True) if (f.get("status") or "active") != "active"]

    cur = db.conn.cursor()
    audit_log = [dict(r) for r in cur.execute("SELECT * FROM audit_log ORDER BY timestamp_utc ASC")]
    collections = db.get_collections()
    in_window = None
    if window[0] or window[1]:
        res = db.query_timeline(window[0], window[1], limit=1)
        in_window = res["total"]

    charts = _charts(db, config, findings, indicators, window) if with_charts else {}

    env = Environment(trim_blocks=True, lstrip_blocks=True, autoescape=False)
    env.filters["md"] = md
    env.filters["fenced"] = fenced
    env.filters["rec"] = clock.recorded
    env.filters["utc"] = clock.corrected
    text = env.from_string(REPORT_TEMPLATE).render(
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
        collections=collections, audit_log=audit_log, retracted=retracted, cited=cited,
        events_referenced=events_referenced, charts=charts,
    )
    return (text, charts) if with_charts else text


def _charts(db, config, findings: list, indicators: list, window: tuple) -> dict:
    """SVG charts keyed by name; a chart is left out when there is nothing to draw."""
    from copilot import charts
    offset = timedelta(minutes=config.clock_offset_minutes)
    out = {}
    times = sorted(t for t in (parse_timestamp(f["time"], "t") for f in findings if f.get("time")) if t)
    markers = [(parse_timestamp(f["time"], "t"), f["number"], f["title"]) for f in findings if f.get("time")]

    def by_type(counts):
        merged = {}
        for b, sources in counts.items():
            for source, n in sources.items():
                t = event_type_for(source)
                merged.setdefault(b, {})[t] = merged.setdefault(b, {}).get(t, 0) + n
        return merged

    def floor(dt, bucket):
        return datetime.fromtimestamp(int(dt.timestamp()) // bucket * bucket, timezone.utc)

    if window[0] and window[1]:
        start, end = parse_timestamp(window[0], "t"), parse_timestamp(window[1], "t")
    elif times:
        start, end = times[0] - timedelta(hours=12), times[-1] + timedelta(hours=12)
    else:
        start = end = None
    if start and end and end > start:
        bucket = charts.pick_bucket((end - start).total_seconds())
        start = floor(start, bucket)
        counts = by_type(db.activity_counts(start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                            end.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket))
        svg = charts.activity_chart(
            "Activity over the incident window", counts, start, end, bucket, offset, markers,
            f"Timeline events per {_bucket_name(bucket)} by type, UTC{' (corrected)' if offset else ''}. "
            f"Numbered markers are findings.")
        if svg:
            out["activity"] = svg

    if len(times) >= 2 and (times[-1] - times[0]) <= timedelta(days=2):
        f_start, f_end = times[0] - timedelta(minutes=30), times[-1] + timedelta(minutes=30)
        bucket = charts.pick_bucket((f_end - f_start).total_seconds())
        f_start = floor(f_start, bucket)
        counts = by_type(db.activity_counts(f_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                            f_end.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket))
        svg = charts.activity_chart(
            "Close-up: first to last finding", counts, f_start, f_end, bucket, offset, markers,
            f"Timeline events per {_bucket_name(bucket)}, 30 minutes either side of the findings.")
        if svg:
            out["focus"] = svg

    seq = charts.sequence_chart(findings, offset)
    if seq:
        out["sequence"] = seq

    label_to_field = {label: field for field, label in INDICATOR_FIELDS}
    flat = [{"field": label_to_field.get(g["label"], ""), "label": g["label"], "value": v["value"],
             "findings": v["findings"]} for g in indicators for v in g["values"]]
    graph = charts.connections_chart(findings, flat)
    if graph:
        out["connections"] = graph
    return out


def _bucket_name(seconds: int) -> str:
    if seconds % 86400 == 0:
        return "day" if seconds == 86400 else f"{seconds // 86400} days"
    if seconds % 3600 == 0:
        return "hour" if seconds == 3600 else f"{seconds // 3600} hours"
    return "minute" if seconds == 60 else f"{seconds // 60} minutes"


def finding_time(db, evidence_ids: list, window: tuple):
    """Recorded time of the primary (first) evidence record, inside the window when possible."""
    for eid in evidence_ids[:1]:
        ev = _evidence(db, str(eid), window)
        if ev and ev["first"]:
            return ev["first"]
    return None
