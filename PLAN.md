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
`corporatesecrets`, run blind once).

## Known weaknesses

- **Large images.** On the OU server (~270,000 logon events) runs without a dossier took 45-110
  minutes and scored around 50%, each question re-investigating from scratch (300-500k tokens).
  With the dossier and the leads one run scored 80.0% in 25 minutes (*entry* 5/6, *ransomware*
  5/5); its times are weaker (17/26: steps given by date only), and the patch level's KB numbers,
  the explicit-credential logons and some tool installs were missed. One run so far; the timeline
  playbook (`26a6528`) targets the times.
- **Consistency.** Questions in one run share only the findings, so two answers can disagree
  (one run called the administrator's home address the attacker in one answer and had the real
  chain in another).
- **Variance.** The same code scored 95.7% and 65.2% on the DC. One run proves little.
- **Only one model measured** (`gpt-5.6-luna`). Local models work but were never benchmarked.
- **Memory** measured on two images only (DC, Injector).
- **A new kind of case:** CorporateSecrets (insider, never tuned on) scored 60.7% blind. Its misses
  are generic gaps: files in user folders are never listed and no file's type is read from its
  content; small sources (browser history) are keyword-searched instead of read whole, so odd
  spellings slip through; logon counts and the last user come from events, never from the SAM or
  Winlogon; the dossier keeps intrusion headings on an insider case. **Addressed in code since,
  measured at 82.1%** (20261021-081326): the user-folder listing with file types and its lead, the
  web-searches lead, the `account_usage` and `browsing` playbooks, SAM in the triage, a dossier for
  either kind of case.

## External review (Codex, 2026-10-20)

An outside review of commit `1a90448` put evidence correctness, access boundaries and reproducible
measurement ahead of new agent behaviour. Fixed right after it:
- **Runtime secrets:** Velociraptor writeback files (client private keys), remap files and
  binaries are git-ignored; the setup docs name remap files `deaddisk-<case>.yaml`.
- **False "not found":** a search the index (first 300 characters per value) can't answer now
  reads the full records, so a negative is a real one.
- **Partial reads:** a collection is marked done only when every reported row was read, or the
  case's row limit stopped the read; otherwise the agent is told the result is incomplete, and
  `check_collection` reads the rest.
- **Exports:** CSVs are written from the same database snapshot as the export's `case.db`, and
  cells that would run as spreadsheet formulas are neutralised.

Still open from the review: steps 6 and 8 below (step 2 is done).

## Where it stands (handover)

The copilot investigates a disk and memory image end to end, writes a case dossier, answers questions
from it with cited records, and builds the report; several investigators share one server with
per-case and per-evidence access. Benchmarks (strict scoring): DC 83-96% (95.7% with the session leads and the MFT check), Injector 71%, OU 80.0%
(~50% before the dossier and the leads);
on CorporateSecrets 60.7% blind (the honest estimate for a new kind of case), 82.1% after generic fixes
for its misses.
From here, improvement comes from use, not from tuning on the benchmarks: analysts correct answers,
add notes and confirm findings (`copilot/feedback.py`), the copilot takes those as given in the case,
and `python -m copilot.feedback export` hands everything they said to whoever improves the knowledge
and prompts (CONTRIBUTING, "Learning from analysts"). Re-run a benchmark (`--from-case`, ~10 min) after
a change to the agent, to check nothing broke.

## Next steps, most valuable first

1. ~~**Reproducible baseline.**~~ Done: CI on Python 3.10-3.12, a test that fails on tracked keys,
   account files or evidence, `requirements-lock.txt` with the exact tested versions for every
   platform, and `case.yaml` / `server.yaml` checked against a schema (`copilot/config_check.py`).
2. ~~**Evidence provenance and access.**~~ Done:
   - A case may name a Velociraptor client or memory image only if no case uses it yet or the
     user can open a case that does (admins: any; `login.new_evidence: admins` keeps unused
     evidence for admins). The memory picker lists only usable images.
   - A client or memory image the case holds data from is locked; copying data checks where
     the data came from.
   - Queued agent collections and memory runs are bound to the evidence they were asked for.
   - Owners can share a case's evidence (with accounts or everyone, optionally with its findings
     and dossier): others start their own case from a copy without opening the original; both
     audit logs record each copy. Copies are full copies (simple, independent); for very large
     cases a read-only link to the shared case's database would save disk later.
   - The report lists each evidence source: host, disk image name and hash (`evidence:` in
     `case.yaml` or the settings form), memory image size and SHA-256 (hashed on first use),
     collections, rows and times; it warns about a changed image or mixed clients.
   - Not covered: any signed-in investigator can still see which Velociraptor clients exist
     (IDs and host names) through the agent's `search_clients` tool, though not use them.
3. ~~**Investigate once, then answer.**~~ Built and partly measured: one longer agent turn
   (`copilot/dossier.py`, 40 steps by default) writes the case dossier (intrusion timeline,
   findings, key entities, hypotheses, contradictions, gaps) before any question; every later
   conversation's system prompt carries it. It runs after the triage in the app and the CLI,
   from the sidebar's **Investigate** button or `/investigate`, and before the questions in a
   benchmark run (`--no-investigate` for the old behaviour). Measured: DC 87.0% at 4.5 min and
   1.18M tokens (9.4 min without it); Injector 58.3%, because *entry* repeated the dossier's
   "web logs not collected" instead of reading them. Fixed after those runs: the dossier's gaps
   are a to-do list for the questions, the investigation is pointed at the web-attack checklist,
   times are copied from the tools. Then reinforced in code: checklists attached by the data (web
   attack, memory), a time check appended to the dossier, Gaps never cut, 3x token budget.
   **Run plan** (each run from an earlier run's triage with `--from-case`, no Velociraptor wait):
   Injector, then DC, then OU if there is time. Read the scorecard's header (commit, data source,
   investigation steps, time-check flags) before the scores. If *entry* on Injector stays low, the
   next fix is a deterministic web-log collection in the triage; if dossiers stay shallow, one
   investigation turn per phase group.
4. **Measure properly.**
   - Two runs per benchmark after each change, recorded in BENCHMARKS.md.
   - Each run saves what it ran with: commit and uncommitted changes and the data source (done),
     case and server settings, knowledge and lesson versions, model settings, normalizer version.
   - ~~Negated claims~~ done (`2fe699f`): a fact named only to deny or doubt it doesn't count.
   - Scoring also checks dates (not only times of day) and whether cited records support the
     sentence. Forbidden claims and
     invalid citations count as failures, not only as side notes.
   - To compare agent or prompt changes without Velociraptor time, start from an earlier run of
     the same image with `--from-case <that run's case>` (done: only its triage is copied).
   - ~~Run CorporateSecrets once, blind.~~ Done: 60.7% (BENCHMARKS.md). Its misses led to generic fixes,
     so no blind benchmark is left: an unbiased number now needs a new image.
5. ~~**More leads in code.**~~ Done:
   - Files whose content is not their name, web searches and YouTube videos (with the CorporateSecrets
     fixes).
   - What each session did, from logon to logoff: events carrying its logon ID (4688 processes, tasks,
     account changes) as proof; programs run (Prefetch, BAM, UserAssist run times; Amcache never
     counts), persistence and files in its time window, labelled as time only (`sessions_to_check`,
     `session_activity`).
   - Timestamps set by hand: MFT SI_Lt_FN / USecZeros and USN BASIC_INFO_CHANGE without a data change.
     Before each investigation the code itself reads the MFT records of the files the sessions to check
     touched (`copilot/checks.py`): the DC's timestomp no longer depends on the model picking the file.
   - Autostart entries that point into user folders or through scripting tools (with the services and
     tasks leads: persistence that differs from the operating system's own).
   - Measured: DC 95.7% strictly (20261021-094310; 100% as run), the timestomp found again after two
     misses; OU 80.0% (20261021-111449; ~50% before).
6. ~~**Durable investigations.**~~ Done:
   - Questions, the investigation, the triage and decided approvals run as jobs in a thread pool of
     the server (`copilot/jobs.py`), not in the page: a reload, a closed tab or another computer
     loses nothing, and the page follows the running job again. Jobs, their progress, the waiting
     approvals and the conversation (saved after every agent step) are in the case database.
   - After a crash or hard kill, interrupted jobs are offered for **Continue**: a question resumes
     from its saved history; collections are reused when the same one is running or usable, approvals
     are claimed once, so retries repeat no side effect. A normal stop lets running jobs finish.
   - Volatility output goes to a temp file and is parsed item by item, capped at `max_rows`.
   - Checked live (real Streamlit, a slow fake model): reload during a question, and a hard kill then
     **Continue**.
   - Not covered: jobs run in the Streamlit server process (one machine); several app processes behind
     a load balancer would need a separate worker reading the same `jobs` table. The CLI still runs
     turns in its own process (its conversation is saved after each exchange).
7. ~~**File activity in triage.**~~ Done and measured (CorporateSecrets 82.1%, DC found `secret.zip`): the triage lists every file in the users'
   Desktop, Documents, Downloads, Pictures, Videos, Music and OneDrive folders
   (`Windows.Search.FileFinder`), types each one up to 50 MB by its first bytes
   (`Generic.Detection.Yara.Glob` with `@file_types`, `knowledge_data/file_types.yaml`), and reads the
   USN journal for archives and disk images in the incident window. Scripts and executables are left out
   of the USN filter (Windows updates create thousands). The DC kept missing `secret.zip` (only in the
   USN journal); CorporateSecrets' secret document and its archive without an extension were in user
   folders no triage listed.
8. **Speed.** Per-step timings in the run log (to tell slow model calls from slow Velociraptor);
   collect triage artifacts in parallel; a shorter system prompt and fewer tools once the leads
   carry more of the work.
9. **Prompt rewrite** once the tools are stable: fewer, shorter rules.
10. **Release.**
    - A person reviews findings before they reach a report.
    - Every change is audited; evidence manifests; export/restore checks.
    - Deployment and backup guidance, PDF export, report sharing.
    - Evaluation across more models and images.
