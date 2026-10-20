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
3. ~~**Investigate once, then answer.**~~ Built, **not measured yet**: one longer agent turn
   (`copilot/dossier.py`, 40 steps by default) writes the case dossier (intrusion timeline,
   findings, key entities, hypotheses, contradictions, gaps) before any question; every later
   conversation's system prompt carries it. It runs after the triage in the app and the CLI,
   from the sidebar's **Investigate** button or `/investigate`, and before the questions in a
   benchmark run (`--no-investigate` for the old behaviour). Next: run DC and Injector (and OU)
   with it and compare score, tokens and minutes with the runs in BENCHMARKS.md. If questions
   still re-investigate everything, tighten the dossier section of the prompt; if the dossier
   misses phases, give the investigation prompt the phase checklists directly.
4. **Measure properly.**
   - Two runs per benchmark after each change, recorded in BENCHMARKS.md.
   - Each run saves what it ran with: commit and uncommitted changes, case and server settings,
     knowledge and lesson versions, model settings, normalizer version.
   - Scoring also checks dates (not only times of day), negated claims ("X did not happen"
     matching X's words) and whether cited records support the sentence. Forbidden claims and
     invalid citations count as failures, not only as side notes.
   - To compare agent or prompt changes without Velociraptor time, keep one triage-only case per
     image (`benchmark run ... --questions none`) and reuse it with `--from-case <that case>`.
   - Run CorporateSecrets once, blind.
5. **More leads in code.**
   - What each attacker session did: files written, tasks and services created, programs run
     between the logon and its logoff (join on logon ID and time).
   - Executions from Prefetch, 4688 and BAM in those windows.
   - Timestomping candidates ($SI vs $FN, zero fractions).
   - Persistence that differs from the operating system's own.
   - Each lead keeps showing its records and join keys, and never presents presence as execution.
6. **Durable investigations.**
   - Jobs, approvals and progress are stored in the case, not the browser session: a refresh or
     restart loses nothing, and retries don't repeat side effects.
   - Volatility output is streamed and capped instead of buffered whole.
   - The orchestration moves out of the Streamlit page into shared services.
7. **File activity in triage.** Archives, scripts and executables created in the incident window
   are only in the USN journal and the MFT, which triage doesn't collect (too large unfiltered).
   A filtered collection (incident window, those extensions) would let the data question see them.
   The DC run keeps missing `secret.zip` for this reason.
8. **Speed.** Per-step timings in the run log (to tell slow model calls from slow Velociraptor);
   collect triage artifacts in parallel; a shorter system prompt and fewer tools once the leads
   carry more of the work.
9. **Prompt rewrite** once the tools are stable: fewer, shorter rules.
10. **Release.**
    - A person reviews findings before they reach a report.
    - Every change is audited; evidence manifests; export/restore checks.
    - Deployment and backup guidance, PDF export, report sharing.
    - Evaluation across more models and images.
