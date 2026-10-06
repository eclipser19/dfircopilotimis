"""
Charts for the HTML report, drawn as static inline SVG.

The report's Content-Security-Policy blocks all scripts (evidence is attacker-controlled),
so charts are computed here and embedded as SVG: no JavaScript, work offline and in print.
Hover details use native SVG <title> tooltips over generous hit areas, and every chart has
a "Show data" table, so no value depends on hover or on colour alone.

Colours are CSS custom properties (see CHART_CSS) from the validated reference palette,
with separately chosen dark-mode steps; categories always keep the same colour.
All text that comes from evidence is HTML-escaped.
"""
import html
import math
from datetime import datetime, timedelta, timezone

from copilot.normalize import parse_timestamp

# Event type -> categorical slot. Fixed, so a type keeps its colour in every chart and report.
TYPE_SLOTS = ["authentication", "execution", "persistence", "filesystem", "script_execution",
              "event_log", "user_activity"]
TYPE_LABELS = {"authentication": "Logons / auth", "execution": "Execution", "persistence": "Persistence",
               "filesystem": "File system", "script_execution": "Scripts", "event_log": "Other event logs",
               "user_activity": "User activity", "other": "Other"}
INDICATOR_SLOTS = [("ip", "IP addresses"), ("user", "Accounts"), ("process", "Processes"),
                   ("path", "Files / paths"), ("hash", "Hashes"), ("command_line", "Command lines")]

CHART_CSS = """
.viz { --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a; --s4:#eda100; --s5:#e87ba4; --s6:#008300; --s7:#4a3aa7;
       --other:#a3a29b; --grid:#e3e2de; --axis:#c3c2bb; --ink:#0b0b0b; --ink2:#52514e; --surface:#fcfcfb;
       --edge:#b9b8b1; --edge-hi:#52514e; margin: 16px 0 24px; }
@media (prefers-color-scheme: dark) {
  .viz { --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500; --s5:#d55181; --s6:#008300; --s7:#9085e9;
         --other:#6b6a64; --grid:#2e2e2b; --axis:#4a4945; --ink:#ffffff; --ink2:#c3c2b7; --surface:#1a1a19;
         --edge:#4a4945; --edge-hi:#c3c2b7; }
}
.viz svg { width: 100%; height: auto; display: block; background: var(--surface); border-radius: 8px; }
.viz .t { fill: var(--ink); font: 12px -apple-system, "Segoe UI", Roboto, sans-serif; }
.viz .t2 { fill: var(--ink2); font: 11px -apple-system, "Segoe UI", Roboto, sans-serif; }
.viz .title { fill: var(--ink); font: 600 14px -apple-system, "Segoe UI", Roboto, sans-serif; }
.viz .grid { stroke: var(--grid); stroke-width: 1; }
.viz .axis { stroke: var(--axis); stroke-width: 1; }
.viz .hit { fill: transparent; }
.viz .hit:hover { fill: var(--ink); fill-opacity: .06; }
.viz .edge { stroke: var(--edge); stroke-width: 1.5; fill: none; }
.viz .edge-hi { stroke: var(--edge-hi); stroke-width: 2; fill: none; }
.viz .marker { stroke: var(--ink2); stroke-width: 1; }
.viz .ring { stroke: var(--surface); stroke-width: 2; }
.viz details { margin-top: 6px; font-size: 12px; }
.viz summary { cursor: pointer; color: var(--ink2); }
"""

W = 960
FONT_W = 6.4  # approx. px per character at 11-12px, for fitting labels


def esc(text) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def _fit(text: str, max_px: float) -> str:
    text = " ".join(str(text).split())
    max_chars = max(4, int(max_px / FONT_W))
    return text if len(text) <= max_chars else text[:max_chars - 1] + "…"


def _parse(ts):
    return parse_timestamp(ts, "time") if ts else None


def _color(event_type: str) -> str:
    return f"var(--s{TYPE_SLOTS.index(event_type) + 1})" if event_type in TYPE_SLOTS else "var(--other)"


def _figure(svg: str, table_head: list, table_rows: list, label: str, extra_class: str = "") -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in table_head)
    rows = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in table_rows)
    table = (f'<details><summary>Show data ({len(table_rows)} rows)</summary><div class="table-wrap">'
             f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div></details>")
    cls = f"viz {extra_class}".strip()
    return f'<figure class="{cls}" aria-label="{esc(label)}">{svg}{table}</figure>'


def nice_axis(peak: float, ticks: int = 4) -> tuple:
    """(axis max, step) with round, whole-number steps for counts."""
    raw = max(peak, 1) / ticks
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 5, 10) if m * mag >= raw)
    step = max(1, step)
    return math.ceil(peak / step) * step, step


def _badge_label(numbers: list) -> str:
    numbers = sorted(numbers)
    if len(numbers) > 2 and numbers == list(range(numbers[0], numbers[-1] + 1)):
        return f"{numbers[0]}–{numbers[-1]}"
    return ",".join(map(str, numbers))


def _group_markers(points: list, merge_px: float = 14) -> list:
    """Findings closer than merge_px share one badge (e.g. '1–5'); its tooltip lists them all."""
    groups = []
    for x, marker in points:
        if groups and x - groups[-1]["x0"] < merge_px:
            groups[-1]["markers"].append(marker)
        else:
            groups.append({"x0": x, "markers": [marker]})
    for g in groups:
        g["x"] = g["x0"]
        g["label"] = _badge_label([m[1] for m in g["markers"]])
        g["width"] = max(16.0, len(g["label"]) * 6.2 + 10)
    return groups


def _marker_levels(spans: list, max_levels: int = 3) -> list:
    """Rows for badges [(center x, width)] so neighbouring badges never overlap."""
    rows_right = []
    levels = []
    for x, width in spans:
        left_edge = x - width / 2
        for level, right_edge in enumerate(rows_right):
            if left_edge >= right_edge + 4:
                rows_right[level] = x + width / 2
                levels.append(level)
                break
        else:
            level = min(len(rows_right), max_levels - 1)
            if level == len(rows_right):
                rows_right.append(x + width / 2)
            else:
                rows_right[level] = max(rows_right[level], x + width / 2)
            levels.append(level)
    return levels


# ---------------------------------------------------------------- time helpers

BUCKETS = [60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]


def pick_bucket(span_seconds: float, max_bins: int = 60) -> int:
    for b in BUCKETS:
        if span_seconds / b <= max_bins:
            return b
    return BUCKETS[-1]


def _tick_step(span_seconds: float) -> int:
    for step in [300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800]:
        if span_seconds / step <= 8:
            return step
    return 604800


def _ticks(start: datetime, end: datetime):
    step = _tick_step((end - start).total_seconds())
    epoch = int(start.timestamp())
    first = epoch - epoch % step + (step if epoch % step else 0)
    t = first
    while t <= end.timestamp():
        yield datetime.fromtimestamp(t, timezone.utc), step
        t += step


def _tick_label(dt: datetime, step: int, prev_day) -> str:
    if step >= 86400:
        return dt.strftime("%d %b")
    return dt.strftime("%H:%M") if dt.date() == prev_day else dt.strftime("%d %b %H:%M")


# ---------------------------------------------------------------- activity (stacked columns)

def activity_chart(title: str, counts: dict, start: datetime, end: datetime, bucket: int,
                   offset: timedelta, markers: list, subtitle: str) -> str:
    """
    counts: {bucket_index: {event_type: n}} in RECORDED time; drawn in corrected time.
    markers: [(recorded datetime, finding number, finding title)].
    """
    left, right, bottom = 56, 16, 40
    plot_w, plot_h = W - left - right, 220
    nbins = max(1, int((end - start).total_seconds() // bucket) + 1)
    span = (end - start).total_seconds() + bucket
    visible = sorted((m for m in markers if start <= m[0] <= end + timedelta(seconds=bucket)), key=lambda m: m[0])
    groups = _group_markers([(left + (m[0] - start).total_seconds() / span * plot_w, m) for m in visible])
    levels = _marker_levels([(g["x"], g["width"]) for g in groups])
    band = 18 * (max(levels) + 1) if levels else 0
    top = 72 + band + 6
    H = top + plot_h + bottom
    slot = plot_w / nbins
    bar_w = max(2.0, min(24.0, slot - 2))
    totals = [sum(counts.get(i, {}).values()) for i in range(nbins)]
    peak = max(totals) if totals else 0
    if not peak:
        return ""
    ymax, ystep = nice_axis(peak)

    def y(v):
        return top + plot_h - v / ymax * plot_h

    def x_of(dt):
        return left + (dt - start).total_seconds() / ((end - start).total_seconds() + bucket) * plot_w

    types_present = [t for t in TYPE_SLOTS + ["other"]
                     if any(t == (k if k in TYPE_SLOTS else "other") for c in counts.values() for k in c)]
    parts = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{esc(title)}">',
             f'<text class="title" x="{left}" y="22">{esc(title)}</text>',
             f'<text class="t2" x="{left}" y="40">{esc(subtitle)}</text>']
    # Legend (identity never by colour alone: names next to swatches)
    lx = left
    for t in types_present:
        color = _color(t)
        label = TYPE_LABELS.get(t, t)
        parts.append(f'<rect x="{lx}" y="48" width="10" height="10" rx="2" fill="{color}"/>'
                     f'<text class="t2" x="{lx + 14}" y="57">{esc(label)}</text>')
        lx += 22 + len(label) * FONT_W
    # Grid + y axis
    for v in range(0, int(ymax) + 1, int(ystep)):
        parts.append(f'<line class="grid" x1="{left}" x2="{W - right}" y1="{y(v):.1f}" y2="{y(v):.1f}"/>'
                     f'<text class="t2" x="{left - 8}" y="{y(v) + 4:.1f}" text-anchor="end">{int(v):,}</text>')
    # Columns: stacked, 2px surface gap between segments, 4px rounded top on the top segment only
    for i in range(nbins):
        col = counts.get(i, {})
        if not col:
            continue
        x0 = left + i * slot + (slot - bar_w) / 2
        merged = {}
        for k, n in col.items():
            key = k if k in TYPE_SLOTS else "other"
            merged[key] = merged.get(key, 0) + n
        order = [t for t in TYPE_SLOTS + ["other"] if t in merged]
        base = 0
        for j, t in enumerate(order):
            n = merged[t]
            y_top, y_bot = y(base + n), y(base)
            h = max(0.0, y_bot - y_top - (2 if j else 0))
            if h >= 0.5:
                if j == len(order) - 1 and h > 4:
                    r = min(4.0, bar_w / 2)
                    parts.append(f'<path fill="{_color(t)}" d="M{x0:.1f},{y_top + h:.1f} V{y_top + r:.1f} '
                                 f'Q{x0:.1f},{y_top:.1f} {x0 + r:.1f},{y_top:.1f} H{x0 + bar_w - r:.1f} '
                                 f'Q{x0 + bar_w:.1f},{y_top:.1f} {x0 + bar_w:.1f},{y_top + r:.1f} '
                                 f'V{y_top + h:.1f} Z"/>')
                else:
                    parts.append(f'<rect fill="{_color(t)}" x="{x0:.1f}" y="{y_top:.1f}" '
                                 f'width="{bar_w:.1f}" height="{h:.1f}"/>')
            base += n
        t0 = start + timedelta(seconds=i * bucket) - offset
        lines = [f"{TYPE_LABELS.get(t, t)}: {merged[t]:,}" for t in order]
        tip = f"{t0:%d %b %H:%M}–{t0 + timedelta(seconds=bucket):%H:%M} UTC · {totals[i]:,} events" + \
              "".join("\n" + line for line in lines)
        parts.append(f'<rect class="hit" x="{left + i * slot:.1f}" y="{top}" width="{slot:.1f}" '
                     f'height="{plot_h}"><title>{esc(tip)}</title></rect>')
    # X axis (corrected time)
    parts.append(f'<line class="axis" x1="{left}" x2="{W - right}" y1="{top + plot_h}" y2="{top + plot_h}"/>')
    prev_day = None
    for dt, step in _ticks(start - offset, end - offset):
        x = x_of(dt + offset)
        if left <= x <= W - right:
            parts.append(f'<text class="t2" x="{x:.1f}" y="{top + plot_h + 16}" text-anchor="middle">'
                         f'{esc(_tick_label(dt, step, prev_day))}</text>')
            prev_day = dt.date()
    # Finding markers: numbered badges in rows above the plot, a hairline down to the axis
    for g, level in zip(groups, levels):
        x, w = g["x"], g["width"]
        cy = 80 + level * 18
        tip = esc("\n".join(f"Finding {n}: {t} ({when - offset:%d %b %H:%M:%S} UTC)" for when, n, t in g["markers"]))
        parts.append(f'<line class="marker" x1="{x:.1f}" x2="{x:.1f}" y1="{cy + 8}" y2="{top + plot_h}"/>'
                     f'<g><rect class="ring" x="{x - w / 2:.1f}" y="{cy - 8}" width="{w:.1f}" height="16" rx="8" '
                     f'fill="var(--ink)"/><text x="{x:.1f}" y="{cy + 3.5}" text-anchor="middle" '
                     f'style="fill:var(--surface);font:600 10px sans-serif">{esc(g["label"])}</text>'
                     f'<title>{tip}</title></g>')
    parts.append("</svg>")
    head = ["From (UTC)", "To (UTC)", "Total"] + [TYPE_LABELS.get(t, t) for t in types_present]
    rows = []
    for i in range(nbins):
        if totals[i]:
            t0 = start + timedelta(seconds=i * bucket) - offset
            col = counts.get(i, {})
            merged = {}
            for k, n in col.items():
                key = k if k in TYPE_SLOTS else "other"
                merged[key] = merged.get(key, 0) + n
            rows.append([f"{t0:%Y-%m-%d %H:%M}", f"{t0 + timedelta(seconds=bucket):%H:%M}", totals[i]] +
                        [merged.get(t, 0) for t in types_present])
    return _figure("".join(parts), head, rows, title)


# ---------------------------------------------------------------- findings sequence (dot timeline)

def sequence_chart(findings: list, offset: timedelta) -> str:
    """One row per timed finding on a shared corrected-UTC axis."""
    timed = [(f, _parse(f["time"])) for f in findings if f.get("time")]
    timed = [(f, t) for f, t in timed if t]
    if len(timed) < 2:
        return ""
    t_min, t_max = min(t for _, t in timed), max(t for _, t in timed)
    pad = max(timedelta(minutes=2), (t_max - t_min) * 0.05)
    start, end = t_min - pad, t_max + pad
    label_w, right, top, row_h = 330, 24, 56, 30
    plot_w = W - label_w - right
    H = top + row_h * len(timed) + 34

    def x_of(dt):
        return label_w + (dt - start).total_seconds() / (end - start).total_seconds() * plot_w

    title = "Findings in sequence"
    parts = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{title}">',
             f'<text class="title" x="16" y="22">{title}</text>',
             f'<text class="t2" x="16" y="40">Each finding at the time of its primary evidence (UTC'
             f'{", corrected" if offset else ""}). Findings without a timestamp are not shown.</text>']
    base_y = top + row_h * len(timed)
    for dt, step in _ticks(start - offset, end - offset):
        x = x_of(dt + offset)
        if label_w <= x <= W - right:
            parts.append(f'<line class="grid" x1="{x:.1f}" x2="{x:.1f}" y1="{top - 6}" y2="{base_y}"/>'
                         f'<text class="t2" x="{x:.1f}" y="{base_y + 16}" text-anchor="middle">'
                         f'{dt:%H:%M}</text>')
    for row, (f, t) in enumerate(timed):
        cy = top + row * row_h + row_h / 2
        x = x_of(t)
        label = f"{f['number']}. {f['title']}"
        conf = (f.get("confidence") or "").lower() or "—"
        near_edge = x > W - 140
        anchor = ' text-anchor="end"' if near_edge else ""
        label_x = x - 10 if near_edge else x + 10
        when = (t - offset).strftime("%Y-%m-%d %H:%M:%S")
        tip = esc(label + "\n" + when + " UTC · confidence " + conf)
        parts.append(f'<text class="t" x="16" y="{cy + 4:.1f}">{esc(_fit(label, label_w - 28))}</text>'
                     f'<line class="grid" x1="{label_w}" x2="{x:.1f}" y1="{cy:.1f}" y2="{cy:.1f}"/>'
                     f'<g><rect class="hit" x="{label_w}" y="{cy - row_h / 2:.1f}" width="{plot_w}" '
                     f'height="{row_h}"/><circle class="ring" cx="{x:.1f}" cy="{cy:.1f}" r="6" '
                     f'fill="var(--s1)"/><text class="t2" x="{label_x:.1f}" y="{cy + 4:.1f}"{anchor}>'
                     f'{esc((t - offset).strftime("%H:%M:%S"))}</text><title>{tip}</title></g>')
    parts.append("</svg>")
    rows = [[f["number"], f["title"], f"{t - offset:%Y-%m-%d %H:%M:%S}", f.get("confidence") or "—",
             f.get("mitre_technique") or "—"] for f, t in timed]
    return _figure("".join(parts), ["#", "Finding", "UTC", "Confidence", "MITRE"], rows, title)


# ---------------------------------------------------------------- connections (bipartite graph)

MAX_INDICATORS = 24


def connections_chart(findings: list, indicators: list) -> str:
    """
    Findings (left) linked to the indicators their evidence contains (right), grouped by
    type. Indicators shared by two or more findings are drawn first and emphasised.
    indicators: [{"field", "label", "value", "findings": [numbers]}]
    """
    if not findings or not indicators:
        return ""
    order = {field: i for i, (field, _) in enumerate(INDICATOR_SLOTS)}
    chosen = sorted(indicators, key=lambda v: (-len(v["findings"]), order.get(v["field"], 9), v["value"]))
    chosen = chosen[:MAX_INDICATORS]
    chosen.sort(key=lambda v: (order.get(v["field"], 9), -len(v["findings"]), v["value"]))
    numbers = sorted({n for v in chosen for n in v["findings"]})
    shown = [f for f in findings if f["number"] in numbers]
    if not shown:
        return ""
    top, row_h = 76, 26
    rows = max(len(shown), len(chosen))
    H = top + rows * row_h + 20
    fx, ix = 300, 600            # node columns
    f_step = (rows * row_h) / max(1, len(shown))
    i_step = (rows * row_h) / max(1, len(chosen))
    fy = {f["number"]: top + f_step * k + f_step / 2 for k, f in enumerate(shown)}
    iy = [top + i_step * k + i_step / 2 for k in range(len(chosen))]
    title = "Connections between findings and indicators"
    parts = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{title}">',
             f'<text class="title" x="16" y="22">{title}</text>',
             f'<text class="t2" x="16" y="40">Lines link a finding to indicators found in the evidence it cites; '
             f'darker lines mark indicators shared by several findings. Hover or click a dot to focus it.</text>']
    parts.append('<circle cx="21" cy="55" r="5" fill="var(--s1)"/><text class="t2" x="30" y="59">Findings</text>')
    lx = 30 + 8 * FONT_W + 14
    for field, label in INDICATOR_SLOTS:
        if any(v["field"] == field for v in chosen):
            slot = order[field] + 2
            parts.append(f'<rect x="{lx}" y="50" width="10" height="10" rx="5" fill="var(--s{slot})"/>'
                         f'<text class="t2" x="{lx + 14}" y="59">{esc(label)}</text>')
            lx += 24 + len(label) * FONT_W
    # Classes tie every edge and node to its finding (f<n>) and indicator (i<k>), so pure CSS
    # (no scripts) can fade everything unrelated to the hovered or clicked node.
    links_of_finding = {}
    for k, v in enumerate(chosen):
        for n in v["findings"]:
            links_of_finding.setdefault(n, []).append(k)
    # Edges first (under the nodes)
    for k, v in enumerate(chosen):
        shared = len(v["findings"]) > 1
        for n in v["findings"]:
            if n in fy:
                y1, y2 = fy[n], iy[k]
                mx = (fx + ix) / 2
                parts.append(f'<path class="e f{n} i{k} {"edge-hi" if shared else "edge"}" '
                             f'd="M{fx + 7},{y1:.1f} C{mx},{y1:.1f} {mx},{y2:.1f} {ix - 7},{y2:.1f}"/>')
    for f in shown:
        n = f["number"]
        y0 = fy[n]
        label = f"{n}. {f['title']}"
        related = " ".join(f"i{k}" for k in links_of_finding.get(n, []))
        parts.append(f'<g class="n f{n} fn{n} {related}" tabindex="0">'
                     f'<rect class="hit" x="8" y="{y0 - 12:.1f}" width="{fx + 8}" height="24"/>'
                     f'<text class="t" x="{fx - 14}" y="{y0 + 4:.1f}" text-anchor="end">'
                     f'{esc(_fit(label, fx - 30))}</text>'
                     f'<circle class="ring" cx="{fx}" cy="{y0:.1f}" r="7" fill="var(--s1)"/>'
                     f'<title>{esc(label)}</title></g>')
    for k, v in enumerate(chosen):
        y0 = iy[k]
        slot = order.get(v["field"], 5) + 2
        shared = len(v["findings"])
        label = _fit(v["value"], W - ix - 40) + (f"  ×{shared}" if shared > 1 else "")
        weight = ' style="font-weight:600"' if shared > 1 else ""
        tip = esc(v["label"] + ": " + v["value"] + "\nFindings: " + ", ".join(map(str, v["findings"])))
        related = " ".join(f"f{n}" for n in v["findings"])
        parts.append(f'<g class="n i{k} in{k} {related}" tabindex="0">'
                     f'<rect class="hit" x="{ix - 12}" y="{y0 - 12:.1f}" width="{W - ix}" height="24"/>'
                     f'<circle class="ring" cx="{ix}" cy="{y0:.1f}" r="{7 if shared > 1 else 6}" '
                     f'fill="var(--s{slot})"/>'
                     f'<text class="t" x="{ix + 14}" y="{y0 + 4:.1f}"{weight}>{esc(label)}</text>'
                     f'<title>{tip}</title></g>')
    rules = [".conn .e, .conn .n { transition: opacity .15s; } .conn .n { cursor: pointer; outline: none; }",
             ".conn .n:focus .ring { stroke: var(--ink); stroke-width: 2.5; }"]
    for n in links_of_finding:
        rules.append(f".conn svg:has(.fn{n}:is(:hover,:focus)) :is(.e,.n):not(.f{n}) {{ opacity: .1; }}"
                     f".conn svg:has(.fn{n}:is(:hover,:focus)) .e.f{n} {{ stroke: var(--ink); stroke-width: 2.5; }}")
    for k in range(len(chosen)):
        rules.append(f".conn svg:has(.in{k}:is(:hover,:focus)) :is(.e,.n):not(.i{k}) {{ opacity: .1; }}"
                     f".conn svg:has(.in{k}:is(:hover,:focus)) .e.i{k} {{ stroke: var(--ink); stroke-width: 2.5; }}")
    parts.insert(1, "<style>" + "".join(rules) + "</style>")
    parts.append("</svg>")
    more = len(indicators) - len(chosen)
    if more > 0:
        parts.insert(-1, f'<text class="t2" x="{ix}" y="{H - 6}">+ {more} more indicators (see Indicators Observed)</text>')
    table = [[v["label"], v["value"], ", ".join(map(str, v["findings"]))] for v in indicators]
    return _figure("".join(parts), ["Type", "Indicator", "Findings"], table, title, "conn")
