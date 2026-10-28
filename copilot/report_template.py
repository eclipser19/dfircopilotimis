# DFIR Copilot — Report Template (Jinja2, rendered with trim_blocks/lstrip_blocks so
# Markdown tables stay contiguous). Only executive_summary, correlations and
# recommendations come from the LLM; everything else is computed from the case database.

REPORT_TEMPLATE = """# Digital Forensics & Incident Response Report

**Case:** {{ case_name | md }}
**Analyst:** {{ analyst | md }}
**Generated:** {{ generated_at }}
{% if unconfirmed %}
**Review:** DRAFT. {{ unconfirmed }} of {{ findings | length }} findings have not been confirmed by an investigator (no ✔ in the Findings Overview).
{% elif confirmed_only %}
**Review:** only findings confirmed by an investigator are included{% if left_out %}; {{ left_out }} unconfirmed finding{{ "s were" if left_out != 1 else " was" }} left out{% endif %}.
{% elif findings %}
**Review:** every finding was confirmed by an investigator.
{% endif %}

---

## 1. Executive Summary

{{ executive_summary | text }}

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
{% if client_id %}
- **Disk evidence:** Velociraptor client {{ client_id | md }}
{% endif %}
{% if memory_image %}
- **Memory image:** {{ memory_image | md }}{% if memory_captured %}, captured {{ memory_captured | md }} (host clock){% endif %}
{% endif %}
{% if clock_skewed %}
- **Clock correction:** the host clock ran {{ clock_offset | abs }} minutes {{ "ahead of" if clock_offset > 0 else "behind" }} true UTC. Times below are shown corrected (**UTC**) and as recorded on the host (**Recorded**).
{% endif %}
{% if evidence_sources %}

**Evidence sources** (collection times are analysis times, UTC)

| Source | Name | Identity | Collections | Rows stored | First collected | Last collected |
|---|---|---|---|---|---|---|
{% for s in evidence_sources %}
| {{ s.kind }} | {{ s.name | md }} | {{ s.identity | md }} | {{ s.collections }} | {{ s.rows }} | {{ s.first }} | {{ s.last }} |
{% endfor %}
{% for w in evidence_warnings %}

**⚠ {{ w | md }}**
{% endfor %}
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
| # | UTC | Recorded | Finding | Confidence | MITRE | Confirmed |
|---|---|---|---|---|---|---|
{% for f in findings %}
| {{ f.number }} | {{ f.time | utc }} | {{ f.time | rec }} | {{ f.title | md }} | {{ (f.confidence or "—") | md }} | {{ (f.mitre_technique or "—") | md }} | {{ "✔" if f.confirmed_by else "—" }} |
{% endfor %}

A finding's time is the earliest timestamp of the first (primary) record it cites.
{% if charts.sequence %}

[[chart:sequence]]
{% endif %}
{% else %}
*No findings were recorded.*
{% endif %}

---

## 4. Evidence Timeline
{% if charts.activity %}

[[chart:activity]]
{% endif %}
{% if charts.focus %}

[[chart:focus]]
{% endif %}

{% if timeline %}
Every timestamp of the records cited by findings{% if has_scope %}, inside the incident window{% endif %}.

| UTC | Recorded | Source | Time field | Event | Evidence | Finding |
|---|---|---|---|---|---|---|
{% for r in timeline %}
| {{ r.ts | utc }} | {{ r.ts | rec }} | {{ r.source | md }} | {{ r.field | md }} | {% if r.meaning %}**{{ r.meaning | md }}** · {% endif %}{{ r.description | md }} | `{{ r.evidence_id }}` | {{ r.findings | sort | join(", ") }} |
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
### 5.{{ f.number }}. {{ f.title | md }}

{% if f.time %}
- **Time:** {{ f.time | utc }} UTC{% if clock_skewed %} (recorded {{ f.time | rec }}){% endif %}

{% else %}
- **Time:** no timestamp in the cited evidence
{% endif %}
- **Confidence:** {{ (f.confidence or "—") | md }}
- **Review:** {% if f.confirmed_by %}confirmed by {{ f.confirmed_by | md }}{% else %}not confirmed by an investigator{% endif %}

{% if f.origin %}
- **Imported from:** {{ f.origin | md }} (copied with its evidence; review it for this case)
{% endif %}
{% if f.mitre_technique %}
- **MITRE ATT&CK:** {{ f.mitre_technique | md }}
{% endif %}

{{ f.description | text }}

| Evidence | Source | UTC | Record |
|---|---|---|---|
{% for e in f.evidence %}
| `{{ e.evidence_id }}` | {{ e.source | md }} | {{ e.first | utc }} | {% if e.meaning %}**{{ e.meaning | md }}** · {% endif %}{{ e.description | md }} |
{% endfor %}

{% else %}
*No findings recorded.*
{% endfor %}
---

## 6. Correlations
{% if charts.connections %}

[[chart:connections]]
{% endif %}

{% if correlations %}
{{ correlations | text }}

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
- `{{ v.value | md }}` (findings {{ v.findings | join(", ") }})
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
{% if events_referenced %}

**Event IDs referenced**

| Event ID | Log | Meaning | Notes |
|---|---|---|---|
{% for ev in events_referenced %}
| {{ ev.id }} | {{ ev.channel | md }} | {{ ev.meaning | md }} | {{ (ev.details or "") | md }} |
{% endfor %}
{% endif %}

---

## 9. Recommendations

{{ recommendations | text }}

---

## Appendix A: Collections

{% if collections %}
| Artifact | Parameters | State | Rows ingested | Error |
|---|---|---|---|---|
{% for c in collections %}
| {{ c.artifact | md }} | {{ c.parameters | md }} | {{ c.state }} | {{ c.rows_ingested }} | {{ c.error | md }} |
{% endfor %}
{% else %}
*No collections recorded.*
{% endif %}

## Appendix B: Cited Evidence Records

The complete original record of every evidence ID cited above, as collected from the image.

{% for e in cited %}
### `{{ e.evidence_id }}` — {{ e.source | md }}

- **Cited by findings:** {{ e.findings | join(", ") }}
{% if e.all_timestamps %}
- **Timestamps (UTC / recorded):** {% for t in e.all_timestamps %}{{ t.timestamp_utc | utc }} / {{ t.timestamp_utc | rec }} ({{ t.timestamp_desc }}){% if not loop.last %}; {% endif %}{% endfor %}

{% else %}
- **Timestamps:** none in this record
{% endif %}

{{ e.raw_json | fenced }}

{% else %}
*No evidence cited.*
{% endfor %}

## Appendix C: Retracted Findings

{% if retracted %}
| Finding | Reason |
|---|---|
{% for r in retracted %}
| {{ r.title | md }} | {{ r.status_reason | md }} |
{% endfor %}
{% else %}
*None.*
{% endif %}

## Appendix D: Query Audit Log

{% if audit_log %}
{% set by_user = audit_log | selectattr("actor") | list %}
| Time (analysis) |{% if by_user %} Investigator |{% endif %} Tool | Query | Rows |
|---|{% if by_user %}---|{% endif %}---|---|---|
{% for log in audit_log %}
| {{ log.timestamp_utc[:19] }} |{% if by_user %} {{ (log.actor or "") | md }} |{% endif %} {{ log.tool_name }} | {{ log.query | md }} | {{ log.row_count }} |
{% endfor %}
{% else %}
*No queries recorded.*
{% endif %}

---

*Report generated by DFIR Copilot. Only the executive summary, correlation analysis and recommendations are written by the AI; all times, evidence and artifact descriptions come from the case database.*
"""
