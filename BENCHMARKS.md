# Benchmark results

How well the copilot answers fixed questions about forensic images whose answers are known.
How to run a benchmark and how scoring works: [README](README.md#benchmark) and
[CONTRIBUTING](CONTRIBUTING.md#benchmarks-and-answer-keys). Add a row here after every run that
matters: run ID, score, and what changed in the code since the previous row.

**Model:** `gpt-5.6-luna` for every run below.
**Score:** facts found (and true-UTC times right) out of those in the case's `benchmark.yaml`. The
key grows as runs reveal verified facts, so a score is only comparable with others on the same
key. Re-score saved runs with `python -m copilot.benchmark score benchmark_results/<run>.json`.
**Strict from `2fe699f`:** a fact named only to deny or doubt it ("injection is undetermined", a list
under "No evidence of:") no longer counts. Every saved run was re-scored then; four changed (DC
105830 and 094310, Injector 100143, OU 085524), each on a claim the answer had denied, and their
rows show the score as run in brackets. From `26a6528` a time that ends a label ("**5 February
23:28:30:** ...") is read as a time; only OU 111449 changed (76.0% as run, 80.0%).

## The benchmarks

| Case | Image | What happened | Questions | Status |
|---|---|---|---|---|
| `szechuan-dc` | DFIR Madness "Szechuan Sauce", domain controller (E01 + memory) | RDP brute force, malware download, service persistence, C2 in memory | 7 (13 facts) | Published solution. Used for tuning since its first runs: no longer blind |
| `injector` | CyberDefenders "Injector" (raw disk + memory, Windows Server 2008) | Web application attacked (SQL injection, file inclusion, web shell), accounts added | 5 (19 facts) | Published writeups. Its runs led to the web-attack knowledge: no longer blind |
| `ou-server2022` | Open University "Compromised Windows Server 2022 (simulation)" (E01, very large logs) | Password guessing, RDP, new domain admin, PsExec task pushing a payload, ransom note | 9 (49 facts) | No published solution: key built from verified records (see its `answer_key.md`). No longer blind |
| `corporatesecrets` | CyberDefenders "CorporateSecrets" (AD1 logical image) | Insider data theft | 8 (22 facts) | Run blind once (20261020-141019, 60.7%). Its misses led to generic fixes (user-folder files and their types, web searches, account usage): no longer blind |

`cases/szechuan/` (the same case's desktop) is the tuning case: it has an answer key but no
benchmark file.

## Results

Minutes are as the scorecard reports them: the questions (and, from 091413, the investigation), without the
triage, on the developer's laptop.
Every run below answered its questions **without** a case dossier. From the commit that added
`copilot/dossier.py`, runs investigate first by default (the investigation's steps, tokens and
minutes count in the totals); note that in each new row, and use `--no-investigate` to compare
with the rows below.

### szechuan-dc

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261015-081138 | 57.9% | 7/11 | 4/8 | 4.5 | First run (the key then had 11 facts). Its misses led to the fixes in `c8859c0` and `653832e` |
| 20261015-083214 | **95.7%** | 13/13 | 9/10 | 9.0 | After those fixes |
| 20261015-103116 | (34.8%) | 8/13 | 0/10 | 15.1 | **Invalid:** the Velociraptor client was still reading the Injector image. Led to the image check (`d533b15`): a run now stops when the time-window triage finds nothing |
| 20261015-105830 | 65.2% (73.9% as run) | 10/13 | 5/10 | 12.4 | Run-to-run variance, plus the download time missing (playbook fixed in `d533b15`). Strictly, one fact less: the attacker's return was credited from a sentence saying it did not return |
| 20261016-124015 | 73.9% | 10/13 | 7/10 | 10.0 | First run with the correlation rule, the new record summaries, leads in `case_summary` and the larger triage (`52663f2`..`9a5a2fc`). The same score as the last valid run had as run. Lost the brute force: the failures carry no source address (RDP with NLA), so the agent refused to tie them to the attacker's address. Missed `secret.zip` and the timestomp (it checked one file). Fixed next: failures without an address grouped by workstation name, NLA note in the entry playbook |
| 20261020-075258 | **91.3%** | 12/13 | 9/10 | 9.4 | With those fixes and 20 tool steps. *entry* 2/2 in 5 steps (the failures without an address grouped by workstation name, tied to the RDP logon that follows); timestomp found ($SI before $FN, zero fractions, USN BASIC_INFO_CHANGE). Missed `secret.zip` again: the archive is only in the USN journal, which no triage collects, and the agent wrote "no archive" after searching only what was collected. One garbled evidence ID |
| 20261020-091413 | 87.0% (78.3% as run) | 11/13 | 9/10 | 6.1 | **First run with the investigation first** (`5df8b0e`): dossier of 9,016 characters in 7 of its 40 steps (408k tokens, 1.6 min); 1.66M tokens in for the whole run. The key's brute-force fact accepted only "4625 / failed logon / password guess", and the answer said "failed authentication attempts": wording added, re-scored (*entry* 2/2). Faster than 075258 (6.1 vs 9.4 min) but the dossier was shallow: it skipped file access, lateral movement and timestomping, and wrote that recipe-file access was "not established" although the collected Lnk records show it. The questions found all three themselves (so they did not get cheaper: 52k to 299k tokens each). Missed `secret.zip` again (USN only), and *memory* named `coreupdater.exe` as the C2 connection's owner instead of `spoolsv.exe`. Fixed next: the investigation must search every phase, qualify every negative with what was searched, and the dossier may be 12,000 characters |
| 20261020-104949 | 87.0% | 11/13 | 9/10 | 4.5 | With the investigation reaching every phase (`fe4f8be`): the dossier now had the file access, timestomp candidates and the RDP to the workstation, in 6 steps (320k tokens). Same score as 091413, but 1.18M tokens in (was 1.66M) and 4.5 min (6.1; 9.4 without a dossier): *entry* answered from the dossier with one tool call (27k tokens). Same two misses (`secret.zip`, `spoolsv.exe`). The dossier (12,791 characters) was cut at 12,000 in the prompts, and it shifted one time by an hour (the RDP to the workstation as 03:36:23 UTC; the *lateral* answer had it right, 02:36:23). Fixed next: copy times from the tools, 16,000-character prompt limit |
| 20261020-124851 | 82.6% | 11/13 | 8/10 | 4.8 | `526db25`, from 104949's triage (no Velociraptor wait). *memory* found the injected `spoolsv.exe` this time; *anti_forensics* missed the timestomp (it checked the shortcut files' MFT records, not the file's). Variance in both directions. 1.10M tokens in |
| 20261021-082137 | 91.3% | 12/13 | 9/10 | 6.1 | `e76f1ba`, from 124851's triage plus the new triage entries (SAM, the user-folder listing, the file-type scan: 0 rows, probably no user file with a time in the window (it scans only those); the USN journal filtered to archives: 27 rows). *data* found `secret.zip` with its time, from the triage's USN rows (every run before missed it); *memory* named the injected `spoolsv.exe` again. *anti_forensics* missed the timestomp again: it checked the malware's MFT record, not the secret file's. 1.34M tokens in |
| 20261021-094310 | **95.7%** (100.0% as run) | 12/13 | 10/10 | 6.1 | `b711a93` (the session, timestamp and autostart leads, and the code's MFT check before the investigation), from 082137's triage. Every fact but one. *anti_forensics* found the timestomp on `Beth_Secret.txt` (missed in the two runs before): its MFT record ($SI created at whole seconds, before $FN) was in the case before the question asked anything, and the dossier already had it as a finding; the code's check reads the MFT records of the files the sessions to check touched. *data* and *end* used `session_activity`. *memory* named `spoolsv.exe` holding the C2 address but called its injection undetermined; scored 100% as run because the scorer then had no denial check (the strict scorer and a tighter key fact don't count it). The dossier shifted one time by an hour (the outbound RDP as 03:36:23 UTC) and its time check flagged it; the *lateral* answer had it right. 1.19M tokens in |

### injector

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261015-094425 | 4.8% | 1/16 | 0/5 | 4.5 | The agent spent all its tool steps without answering, and the web server's logs were never read. Fixed by the wrap-up when the steps run out (`4591811`), Apache log times and `Generic.Detection.Logs` (`ea57106`), the web-attack playbook |
| 20261015-095938 | 69.6% | 13/18 | 3/5 | 4.7 | 75.0% (14/19) once the key's matching was corrected |
| 20261015-112120 | **83.3%** | 15/19 | 5/5 | 16.2 | Commands found in memory (several words in one strings pass, `8f67eca`) |
| 20261016-130324 | 62.5% | 12/19 | 3/5 | 18.4 | Same changes. Regression on two questions. *system*: called the web server IIS (a checklist line added for OU pointed at W3SVC and `C:\inetpub`; this server has IIS installed too, but XAMPP serves the site). *entry* 0/5: spent its 15 steps on IIS logs and memory, found the Apache logs on its last step and never read them. Fixed next: no IIS pull in the system checklist, all candidate web logs in one FileFinder call (`SearchFilesGlobTable`), 20 tool steps |
| 20261020-072754 | 70.8% | 13/19 | 4/5 | 7.9 | With those fixes. Both targets fixed: *system* 5/5 (XAMPP named), *entry* 5/5 (Apache logs found and read; was 0/5), and the run took half the time. Three questions the fixes did not touch dropped: *uploads* 1/4 (it described the web shell's commands without naming the `cmd` parameter and skipped the sqlmap uploader), *accounts* and *commands* (the `net localgroup` and `netsh` commands not searched for in memory this time; 2/2 in the run before) |
| 20261020-100143 | 54.2% (58.3% as run) | 12/19 | 1/5 | 7.2 | First Injector run with the investigation first (`fe4f8be`). *entry* 1/5 in 3 steps: the dossier said the web server's access logs were "not collected" and the question took that as the answer instead of reading them (072754 read them: 5/5), so the attacker IP, sqlmap and the file-inclusion requests were missed, and *uploads* lost the `cmd` parameter and the sqlmap uploader. *accounts* missed the `hacker` RDP-group change that *commands* found in memory. 1.45M tokens in. Fixed next: the dossier's gaps are a to-do list for the questions, and the investigation is pointed at the web-attack checklist when a web server runs. Strictly, one time less: the web shell's time was taken from a sentence saying no such request was recovered |
| 20261020-125447 | 70.8% | 14/19 | 3/5 | 9.2 | `526db25`, from 100143's triage. The investigation read the Apache logs (web-attack checklist attached by the data): *entry* 4/5 with one tool call (was 1/5), *uploads* found the `cmd` parameter. Missed: sqlmap's first-request time, the sqlmap uploader in *uploads* (*commands* found it), `netsh` this time. 1.76M tokens in |

### corporatesecrets

The only run on an image the copilot was never tuned on, and the only insider (not intrusion) case.

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261020-141019 | **60.7%** (64.3% re-scored) | 14/22 (15) | 3/6 | 7.7 | **Blind.** `ead4457` + local changes, investigation first (dossier 12,587 characters, 8 steps, 5.1 min); 1.31M tokens in; 0 forbidden claims, 0 uncorrected times, 1 garbled ID. Strong where the triage collects the answer: *system* 5/5, *privacy_tools* 3/3 (Tor Browser in the non-standard folder, its user, launch counts), *installs*, the hacking video to the second. Misses, by cause: (1) **answered from another source**: *accounts* 0/2 used the logon events (last interactive logon, 4624 counts) and never the registry's own answers (Winlogon last user name, SAM logon count); (2) **keyword search over small sources**: *web* missed the search typed with doubled letters and the VSCO search, in browser histories of 63 rows it could have read whole; (3) **files never listed or opened**: a secret document in a user's Documents and an archive without an extension (file type only from its content) are on no triage list; *archives* also tied 7-Zip to the wrong user and missed its last run. Re-scored: *deleted* named Hansel's deleted dog photo by its original path, not its `$R` name (key widened). Probably 2/2 there: the deleted company-secrets document may be the `Document1.docx` it listed (the dossier pairs it with `$RQ1FSDY.docx`), not checked yet. Two credits are generous: *documents* gave the RecentDocs key's write time as "last .docx" (the matching time is elsewhere in the answer), *installs* said LibreCAD was not shown to run (Prefetch shows it did). The dossier kept intrusion headings ("Intrusion timeline", C2) on an insider case |
| 20261021-081326 | **82.1%** | 19/22 | 4/6 | 6.0 | `e76f1ba`, from 141019's triage plus the new triage entries (SAM 20 rows, user-folder listing 78, file-type scan 6). **Not blind:** these fixes came from 141019's misses. Fixed as intended: *accounts* 2/2 (SAM logon counts exactly; both last-user values with their sources: it judged the logon screen's LastLoggedOnUser and the latest logon over Winlogon's LastUsedUsername, which the key uses), *web* found the search typed with doubled letters (from the web-searches lead, answered in 3 steps), *documents* found `secret.odt` (the listing), *archives* found the extensionless 7-Zip archive `vegetable` (the type scan's lead). Still missed: the VSCO search (in the dossier, left out of the answer as not company-relevant), 7-Zip's last run time, the deleted company-secrets document. Lost to variance: Tor Browser's `C:\Program1` folder (found in 141019). On this folder image, creation times are the extraction's (2026): the dossier noticed and used the 2020 times. 0.96M tokens in (1.31M) |

### ou-server2022

Scores on the **current key (49 facts)**; the score each run got on the key of its day in brackets.

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261015-123740 | 52.0% (65.5% on 40 facts) | 29/49 | 10/26 | 26.5 | Blind run the key was built from. 2 forbidden claims: it pinned the administrator's own RDP logon on the guessing address, and called Edge's `cookie_exporter.exe` attacker tooling. It read Amcache times as run times |
| 20261016-085524 | 40.0% (41.3% as run on this key, 46.6% on 40) | 22/49 | 8/26 | 110.1 | After "correlate before claiming" (`52663f2`). No forbidden claims on that key, but it hedged where the record summaries hid the logon's source IP and the task's arguments. The event-log triage was still running when the questions started. Fixed: summaries (`a7bceca`), runs wait for triage. Strictly, one fact less: Domain Admins was listed under "no evidence of" |
| 20261016-111125 | 50.7% (50.0% on 45) | 27/49 | 11/26 | 45.1 | Found the successful guessing, the RDP as Administrator, the password spreadsheet and a remote folder. Each question re-investigated everything (300-500k tokens), and the answers disagreed (one called the administrator's home address the attacker). Led to the leads in `case_summary` (`9a5a2fc`) |
| 20261021-111449 | **80.0%** (76.0% as run) | 43/49 | 17/26 | 24.6 | `b711a93` + local changes, from 111125's triage plus the new triage entries (SAM 8 rows, user-folder listing 679, file-type scan 299, USN filtered to archives 267). First OU run with the investigation first (dossier 12,000 characters, 7 steps, 487k tokens, 2.0 min), the leads (sessions, hand-set timestamps, autostarts) and the code's MFT check. The questions that need a few events out of hundreds of thousands gained most: *entry* 5/6 (was 1/6), *ransomware* 5/5 (1/5), *accounts* 5/5 (3/5), *identifiers* 7/8 (3/8), *timeline* 9/9 facts (6/9). Missed: the patch level's KB numbers (it gave the build and said later updates were absent), the RDP as Administrator and then the new `admin` from 185.229.66.183, Nmap/Npcap's install and the explicit-credential (4648) logons to two desktops in *tools* (3/5, was 4/5), the `account_password.xlsx` shortcut in *data*, and 185.239.106.67. Times are the weak part (17/26; 14/26 as run, when the scorer missed three times written as labels, "**5 February 23:28:30:**"): the *timeline* answer gave one attacker address's logons as "6–9 February" with no time and `rename.exe` by its Amcache date, and *tools* left out when the tools arrived although the dossier had it. Fixed next (`26a6528`): a timeline playbook and dossier wording (every step with its time from its record, each source's first logon, each tool's arrival). 0 forbidden claims, 0 uncorrected times, 0 invalid IDs; the same score strictly. 1.98M tokens in, 24.6 min (45-110 before) |

## What the numbers say so far

- On the two images with published solutions the agent reaches 70-95% when the setup is right.
  Variance between runs is large and sits in single questions: the same Injector *commands*
  question scored 2/2 and then 0/2 with no change to anything it uses; DC scored 95.7% then 65.2%.
  Judge a change on the questions it targets and on at least two runs, never one total.
- Most big drops were setup problems, not reasoning: the wrong image, triage still running,
  logs never read. The runner now catches the first two (image check, triage wait, and a warning
  under **Setup** in the scorecard).
- The dossier (investigate once, then answer) makes runs cheaper when it is broad: DC went from
  9.4 min without it to 4.5 min and 1.18M tokens, at the same score. But a question trusts it: when
  the dossier says data was not collected, the question must collect it, not repeat the gap (Injector
  100143 lost its *entry* question that way).
- On an image it was never tuned on (CorporateSecrets, an insider case) it scored 60.7% (64.3% with
  the deleted file it named by its original path). It answers well and carefully (no forbidden claims)
  what the triage collects; it misses what needs a file listed or opened, the registry's own count or
  last-user values, and text that keyword search can't match. Expect about 60% on a new kind of case
  before analysts' notes and corrections. Generic fixes for those misses (files in user folders and
  their types, decoded web searches, an account-usage playbook) took it to 82.1%, and gave the DC the
  archive no run had found before: what the triage collects decides most of the score.
- Misses that came and went between runs stopped when code, not the model, decides what is looked at:
  the archive only in the USN journal (a filtered USN collection in the triage), the timestomp (the MFT
  records of every file the sessions touched, read before the investigation). DC 95.7% strictly (094310, 100% as run) after
  both; prompt wording alone never held for long.
- On a large server image (OU, ~270,000 logon events) the agent stayed near 50% without a dossier,
  losing most on the entry and ransomware questions, where it has to pick the right few events out
  of hundreds of thousands. With the dossier and the leads in `case_summary` (logons per source
  address, sessions, account changes, tasks...) it scored 80.0% (111449) in 25 minutes instead of
  45-110: *entry* 5/6 and *ransomware* 5/5. One run; times (17/26) are now the weaker part there.
- Scores are strict from `2fe699f` (a fact named only to deny it doesn't count). Before that, a
  "100%" could hide a hedge: the DC's 100% (094310) was 95.7% strictly.
