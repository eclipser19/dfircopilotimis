# DFIR Copilot: Development Plan

LLM-driven DFIR copilot: Velociraptor collects from a forensic image (and Volatility 3 reads a
memory image), results are normalized into a local case database, the agent investigates through
database tools and records findings, and a templated DFIR report is generated from those findings.

Legend: [x] done and tested · [~] partially done · [ ] not started.
Where it stands in numbers: [BENCHMARKS.md](BENCHMARKS.md). How to work on it: [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Done

**Collection and safety.** Lazy Velociraptor gRPC client; every value passed as a VQL environment
variable, never formatted into query text; case pinned to one client; artifact allowlist plus hard
denylist; raw server VQL off by default; honest RUNNING / FINISHED / ERROR states and
`check_collection`; deterministic evidence IDs (re-collecting doesn't duplicate). The agent's own
collections are targeted follow-ups. Heavy artifacts need a filter, parameter names must exist,
and the investigator approves each one. Explanations for empty, failed, truncated and
past-the-row-limit collections. Dead-disk limits known per artifact (`live_only`).

**Normalization.** Timestamps found by value anywhere in a row, one timeline event per distinct
time, entities for pivoting, event types, FTS5 trigram search. One-line descriptions that lead with
the deciding fields (Windows events: logon type, account, source IP, workstation, logon ID; tasks:
command and arguments; deleted files: original path; downloads: URL or none).

**Analysis tools.** Timeline, histogram, context window, search, pivot, event detail, findings.
`case_summary` with **leads computed without the model** (logons grouped per source address,
account and group changes, services, tasks, log clearing, downloads, programs in user folders).
`logon_summary`. Knowledge base (artifacts, event IDs, playbooks attached to matching questions,
ForensicArtifacts "where is it stored" reference), lessons approved by people.

**Answer quality rules.** Corrected (true UTC) times given to the model, never computed by it;
"nothing found" only for searched, covered periods; attacker attribution only from the intrusion
on; **correlate before claiming** (two records, shared keys, open the record before calling a field
missing). "High" confidence is refused for single-record findings.

**Memory.** Volatility 3 with a plugin allowlist, memory triage, offline symbols, multi-word strings
search, own per-process search plugin (text / YARA).

**Report and UI.** Report built from the database (the model writes only the narrative), HTML with
static SVG charts and a CSP, Markdown, exports. Streamlit app for several signed-in investigators
(per-session cases, owners/members, approvals queue, audit log); CLI. Any OpenAI-compatible model,
local ones included.

**Benchmarks.** Runner (fresh case, triage, fixed questions, scoring in code: facts, true-UTC times,
uncorrected times, invalid evidence IDs, forbidden claims), image check, triage wait, re-scoring,
evidence dump for building keys. Four benchmarks (`szechuan-dc`, `injector`, `ou-server2022`,
held-out `corporatesecrets`).

## Known weaknesses

- **Large images.** On the OU server (~270,000 logon events) runs take 45-110 minutes and score
  around 50%. Each question used 300-500k tokens re-investigating from scratch. The entry and
  ransomware questions are the weakest. The leads in `case_summary` are the first answer to this;
  not yet measured.
- **Consistency.** Questions in one run share only the findings, so two answers can disagree
  (one run called the administrator's home address the attacker in one answer and had the real
  chain in another).
- **Variance.** The same code scored 95.7% and 73.9% on the DC. One run proves little.
- **Only one model measured** (`gpt-5.6-luna`). Local models work but were never benchmarked.
- **Memory** measured on two images only (DC, Injector).
- **CorporateSecrets** (the last blind benchmark) has never been run: it needs the AD1 extracted
  first (see its `answer_key.md`).

## Next steps, most valuable first

1. **Investigate once, then answer.** One longer agent turn that builds the intrusion timeline
   and records findings ("investigate this case"), before any question. Questions then start from
   the findings and the leads, and only check what they add. This should make answers consistent
   and much cheaper. It fits the app as an "Investigate" button, and the benchmark as a step
   before the questions.
2. **Measure properly.**
   - Two runs per benchmark after each change, recorded in BENCHMARKS.md.
   - To compare agent or prompt changes without Velociraptor time, keep one triage-only case per
     image (`benchmark run ... --questions none`) and reuse it with `--from-case <that case>`.
   - Run CorporateSecrets once, blind.
3. **More leads in code.**
   - What each attacker session did: files written, tasks and services created, programs run
     between the logon and its logoff (join on logon ID and time).
   - Executions from Prefetch, 4688 and BAM in those windows.
   - Timestomping candidates ($SI vs $FN, zero fractions).
   - Persistence that differs from the operating system's own.
4. **Speed.** Per-step timings in the run log (to tell slow model calls from slow Velociraptor);
   collect triage artifacts in parallel; a shorter system prompt and fewer tools once the leads
   carry more of the work.
5. **Prompt rewrite** once the tools are stable: fewer, shorter rules.
6. **Report:** PDF export; report sharing.
7. **Environment:** image hashing and the read-only mount procedure recorded in the case file.
