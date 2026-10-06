# DFIR Copilot — Report Template (Jinja2, rendered with trim_blocks/lstrip_blocks so
# Markdown tables stay contiguous). Only executive_summary, correlations and
# recommendations come from the LLM; everything else is computed from the case database.

REPORT_TEMPLATE = """# Digital Forensics & Incident Response Report

**Case:** {{ case_name }}
**Analyst:** {{ analyst }}
**Generated:** {{ generated_at }}

---

## 1. Executive Summary

{{ executive_summary }}

---

## 2. Scope & Evidence

{% if has_scope %}
- **Incident window:** {{ start_time }} → {{ end_time }}
{% else %}
- **Scope:** General triage (no incident window provided)
{% endif %}
{% if scope_description %}
- **Background:** {{ scope_description | md }}
{% endif %}
{% if clock_skewed %}
- **Clock correction:** the host clock ran {{ clock_offset | abs }} minutes {{ "ahead of" if clock_offset > 0 else "behind" }} true UTC. Times below are shown corrected (**UTC**) and as recorded on the host (**Recorded**).
{% endif %}

| Source | Type | Records | With timestamps | Earliest (recorded) | Latest (recorded) |
|---|---|---|---|---|---|
{% for src in stats.by_source %}
| {{ src.source | md }} | {{ src.event_type }} | {{ src.records }} | {{ src.dated_records }} | {{ src.earliest | rec }} | {{ src.latest | rec }} |
{% endfor %}

**Records:** {{ stats.total_records }} ({{ stats.undated_records }} without timestamps) · **Timeline events:** {{ stats.timeline_events }}{% if in_window is not none %} ({{ in_window }} inside the incident window){% endif %}


---

## 3. Findings Overview

{% if findings %}
| # | UTC | Recorded | Finding | Confidence | MITRE |
|---|---|---|---|---|---|
{% for f in findings %}
| {{ f.number }} | {{ f.time | utc }} | {{ f.time | rec }} | {{ f.title | md }} | {{ f.confidence or "—" }} | {{ f.mitre_technique or "—" }} |
{% endfor %}

Finding times are taken from the earliest timestamp of the evidence each finding cites.
{% else %}
*No findings were recorded.*
{% endif %}

---

## 4. Evidence Timeline

{% if timeline %}
Every timestamp of the records cited by findings{% if has_scope %}, inside the incident window{% endif %}.

| UTC | Recorded | Source | Time field | Event | Evidence | Finding |
|---|---|---|---|---|---|---|
{% for r in timeline %}
| {{ r.ts | utc }} | {{ r.ts | rec }} | {{ r.source | md }} | {{ r.field | md(40) }} | {{ r.description | md(160) }} | `{{ r.evidence_id }}` | {{ r.findings | sort | join(", ") }} |
{% endfor %}
{% if timeline_truncated %}

*Showing the first {{ max_timeline }} rows.*
{% endif %}
{% else %}
*No timestamped evidence is cited by findings.*
{% endif %}

---

## 5. Detailed Findings

{% for f in findings %}
### 5.{{ f.number }}. {{ f.title }}

{% if f.time %}
- **Time:** {{ f.time | utc }} UTC{% if clock_skewed %} (recorded {{ f.time | rec }}){% endif %}

{% else %}
- **Time:** no timestamp in the cited evidence
{% endif %}
- **Confidence:** {{ f.confidence or "—" }}
{% if f.mitre_technique %}
- **MITRE ATT&CK:** {{ f.mitre_technique }}
{% endif %}

{{ f.description }}

| Evidence | Source | UTC | Record |
|---|---|---|---|
{% for e in f.evidence %}
| `{{ e.evidence_id }}` | {{ e.source | md }} | {{ e.first | utc }} | {{ e.description | md(200) }} |
{% endfor %}

{% else %}
*No findings recorded.*
{% endfor %}
---

## 6. Correlations

{% if correlations %}
{{ correlations }}

{% endif %}
{% if related %}
Findings linked by shared evidence or occurring within {{ related_minutes }} minutes of each other:

| Findings | Link |
|---|---|
{% for r in related %}
| {{ r.a }} ↔ {{ r.b }} | {{ r.reason | md }} |
{% endfor %}
{% elif not correlations %}
*No correlations identified.*
{% endif %}

---

## 7. Indicators Observed

{% if indicators %}
Values extracted from the evidence cited by findings.

{% for group in indicators %}
**{{ group.label }}**

{% for v in group["values"] %}
- `{{ v.value | md(200) }}` (findings {{ v.findings | join(", ") }})
{% endfor %}

{% endfor %}
{% else %}
*No indicators extracted from cited evidence.*
{% endif %}
{% if iocs_searched %}
**Known IOCs from the case file**

| IOC | Type | Matching records |
|---|---|---|
{% for ioc in iocs_searched %}
| {{ ioc.value | md }} | {{ ioc.type }} | {{ ioc.hits }} |
{% endfor %}
{% endif %}

---

## 8. Artifacts, Locations & Meanings

| Source | What it is | Location on disk | What it shows |
|---|---|---|---|
{% for a in artifacts %}
| {{ a.source | md }} | {{ a.what | md }} | {{ a.location | md }} | {{ a.meaning | md }} |
{% endfor %}

---

## 9. Recommendations

{{ recommendations }}

---

## Appendix A: Collections

{% if collections %}
| Artifact | Parameters | State | Rows ingested | Error |
|---|---|---|---|---|
{% for c in collections %}
| {{ c.artifact | md }} | {{ c.parameters | md(160) }} | {{ c.state }} | {{ c.rows_ingested }} | {{ c.error | md(120) }} |
{% endfor %}
{% else %}
*No collections recorded.*
{% endif %}

## Appendix B: Query Audit Log

{% if audit_log %}
| Time (analysis) | Tool | Query | Rows |
|---|---|---|---|
{% for log in audit_log %}
| {{ log.timestamp_utc[:19] }} | {{ log.tool_name }} | {{ log.query | md(160) }} | {{ log.row_count }} |
{% endfor %}
{% else %}
*No queries recorded.*
{% endif %}

---

*Report generated by DFIR Copilot. Only the executive summary, correlation analysis and recommendations are written by the AI; all times, evidence and artifact descriptions come from the case database.*
"""
