# Benchmark results

How well the copilot answers fixed questions about forensic images whose answers are known.
How to run a benchmark and how scoring works: [README](README.md#benchmark) and
[CONTRIBUTING](CONTRIBUTING.md#benchmarks-and-answer-keys). Add a row here after every run that
matters: run ID, score, and what changed in the code since the previous row.

**Model:** `gpt-5.6-luna` for every run below.
**Score:** facts found (and true-UTC times right) out of those in the case's `benchmark.yaml`. The
key grows as runs reveal verified facts, so a score is only comparable with others on the same
key. Re-score saved runs with `python -m copilot.benchmark score benchmark_results/<run>.json`.

## The benchmarks

| Case | Image | What happened | Questions | Status |
|---|---|---|---|---|
| `szechuan-dc` | DFIR Madness "Szechuan Sauce", domain controller (E01 + memory) | RDP brute force, malware download, service persistence, C2 in memory | 7 (13 facts) | Published solution. Used for tuning since its first runs: no longer blind |
| `injector` | CyberDefenders "Injector" (raw disk + memory, Windows Server 2008) | Web application attacked (SQL injection, file inclusion, web shell), accounts added | 5 (19 facts) | Published writeups. Its runs led to the web-attack knowledge: no longer blind |
| `ou-server2022` | Open University "Compromised Windows Server 2022 (simulation)" (E01, very large logs) | Password guessing, RDP, new domain admin, PsExec task pushing a payload, ransom note | 9 (49 facts) | No published solution: key built from verified records (see its `answer_key.md`). No longer blind |
| `corporatesecrets` | CyberDefenders "CorporateSecrets" (AD1 logical image) | Insider data theft | 8 (22 facts) | **Held out**: never run, never tuned on. The only blind benchmark left |

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
| 20261015-105830 | 73.9% | 11/13 | 6/10 | 12.4 | Run-to-run variance, plus the download time missing (playbook fixed in `d533b15`) |
| 20261016-124015 | 73.9% | 10/13 | 7/10 | 10.0 | First run with the correlation rule, the new record summaries, leads in `case_summary` and the larger triage (`52663f2`..`9a5a2fc`). Same score as the last valid run. Lost the brute force: the failures carry no source address (RDP with NLA), so the agent refused to tie them to the attacker's address. Missed `secret.zip` and the timestomp (it checked one file). Fixed next: failures without an address grouped by workstation name, NLA note in the entry playbook |
| 20261020-075258 | **91.3%** | 12/13 | 9/10 | 9.4 | With those fixes and 20 tool steps. *entry* 2/2 in 5 steps (the failures without an address grouped by workstation name, tied to the RDP logon that follows); timestomp found ($SI before $FN, zero fractions, USN BASIC_INFO_CHANGE). Missed `secret.zip` again: the archive is only in the USN journal, which no triage collects, and the agent wrote "no archive" after searching only what was collected. One garbled evidence ID |
| 20261020-091413 | 87.0% (78.3% as run) | 11/13 | 9/10 | 6.1 | **First run with the investigation first** (`5df8b0e`): dossier of 9,016 characters in 7 of its 40 steps (408k tokens, 1.6 min); 1.66M tokens in for the whole run. The key's brute-force fact accepted only "4625 / failed logon / password guess", and the answer said "failed authentication attempts": wording added, re-scored (*entry* 2/2). Faster than 075258 (6.1 vs 9.4 min) but the dossier was shallow: it skipped file access, lateral movement and timestomping, and wrote that recipe-file access was "not established" although the collected Lnk records show it. The questions found all three themselves (so they did not get cheaper: 52k to 299k tokens each). Missed `secret.zip` again (USN only), and *memory* named `coreupdater.exe` as the C2 connection's owner instead of `spoolsv.exe`. Fixed next: the investigation must search every phase, qualify every negative with what was searched, and the dossier may be 12,000 characters |
| 20261020-104949 | 87.0% | 11/13 | 9/10 | 4.5 | With the investigation reaching every phase (`fe4f8be`): the dossier now had the file access, timestomp candidates and the RDP to the workstation, in 6 steps (320k tokens). Same score as 091413, but 1.18M tokens in (was 1.66M) and 4.5 min (6.1; 9.4 without a dossier): *entry* answered from the dossier with one tool call (27k tokens). Same two misses (`secret.zip`, `spoolsv.exe`). The dossier (12,791 characters) was cut at 12,000 in the prompts, and it shifted one time by an hour (the RDP to the workstation as 03:36:23 UTC; the *lateral* answer had it right, 02:36:23). Fixed next: copy times from the tools, 16,000-character prompt limit |
| 20261020-124851 | 82.6% | 11/13 | 8/10 | 4.8 | `526db25`, from 104949's triage (no Velociraptor wait). *memory* found the injected `spoolsv.exe` this time; *anti_forensics* missed the timestomp (it checked the shortcut files' MFT records, not the file's). Variance in both directions. 1.10M tokens in |

### injector

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261015-094425 | 4.8% | 1/16 | 0/5 | 4.5 | The agent spent all its tool steps without answering, and the web server's logs were never read. Fixed by the wrap-up when the steps run out (`4591811`), Apache log times and `Generic.Detection.Logs` (`ea57106`), the web-attack playbook |
| 20261015-095938 | 69.6% | 13/18 | 3/5 | 4.7 | 75.0% (14/19) once the key's matching was corrected |
| 20261015-112120 | **83.3%** | 15/19 | 5/5 | 16.2 | Commands found in memory (several words in one strings pass, `8f67eca`) |
| 20261016-130324 | 62.5% | 12/19 | 3/5 | 18.4 | Same changes. Regression on two questions. *system*: called the web server IIS (a checklist line added for OU pointed at W3SVC and `C:\inetpub`; this server has IIS installed too, but XAMPP serves the site). *entry* 0/5: spent its 15 steps on IIS logs and memory, found the Apache logs on its last step and never read them. Fixed next: no IIS pull in the system checklist, all candidate web logs in one FileFinder call (`SearchFilesGlobTable`), 20 tool steps |
| 20261020-072754 | 70.8% | 13/19 | 4/5 | 7.9 | With those fixes. Both targets fixed: *system* 5/5 (XAMPP named), *entry* 5/5 (Apache logs found and read; was 0/5), and the run took half the time. Three questions the fixes did not touch dropped: *uploads* 1/4 (it described the web shell's commands without naming the `cmd` parameter and skipped the sqlmap uploader), *accounts* and *commands* (the `net localgroup` and `netsh` commands not searched for in memory this time; 2/2 in the run before) |
| 20261020-100143 | 58.3% | 12/19 | 2/5 | 7.2 | First Injector run with the investigation first (`fe4f8be`). *entry* 1/5 in 3 steps: the dossier said the web server's access logs were "not collected" and the question took that as the answer instead of reading them (072754 read them: 5/5), so the attacker IP, sqlmap and the file-inclusion requests were missed, and *uploads* lost the `cmd` parameter and the sqlmap uploader. *accounts* missed the `hacker` RDP-group change that *commands* found in memory. 1.45M tokens in. Fixed next: the dossier's gaps are a to-do list for the questions, and the investigation is pointed at the web-attack checklist when a web server runs |
| 20261020-125447 | 70.8% | 14/19 | 3/5 | 9.2 | `526db25`, from 100143's triage. The investigation read the Apache logs (web-attack checklist attached by the data): *entry* 4/5 with one tool call (was 1/5), *uploads* found the `cmd` parameter. Missed: sqlmap's first-request time, the sqlmap uploader in *uploads* (*commands* found it), `netsh` this time. 1.76M tokens in |

### ou-server2022

Scores on the **current key (49 facts)**; the score each run got on the key of its day in brackets.

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261015-123740 | 52.0% (65.5% on 40 facts) | 29/49 | 10/26 | 26.5 | Blind run the key was built from. 2 forbidden claims: it pinned the administrator's own RDP logon on the guessing address, and called Edge's `cookie_exporter.exe` attacker tooling. It read Amcache times as run times |
| 20261016-085524 | 41.3% (46.6% on 40) | 23/49 | 8/26 | 110.1 | After "correlate before claiming" (`52663f2`). No forbidden claims on that key, but it hedged where the record summaries hid the logon's source IP and the task's arguments. The event-log triage was still running when the questions started. Fixed: summaries (`a7bceca`), runs wait for triage |
| 20261016-111125 | 50.7% (50.0% on 45) | 27/49 | 11/26 | 45.1 | Found the successful guessing, the RDP as Administrator, the password spreadsheet and a remote folder. Each question re-investigated everything (300-500k tokens), and the answers disagreed (one called the administrator's home address the attacker). Led to the leads in `case_summary` (`9a5a2fc`) |

## What the numbers say so far

- On the two images with published solutions the agent reaches 70-95% when the setup is right.
  Variance between runs is large and sits in single questions: the same Injector *commands*
  question scored 2/2 and then 0/2 with no change to anything it uses; DC scored 95.7% then 73.9%.
  Judge a change on the questions it targets and on at least two runs, never one total.
- Most big drops were setup problems, not reasoning: the wrong image, triage still running,
  logs never read. The runner now catches the first two (image check, triage wait, and a warning
  under **Setup** in the scorecard).
- The dossier (investigate once, then answer) makes runs cheaper when it is broad: DC went from
  9.4 min without it to 4.5 min and 1.18M tokens, at the same score. But a question trusts it: when
  the dossier says data was not collected, the question must collect it, not repeat the gap (Injector
  100143 lost its *entry* question that way).
- On a large server image (OU, ~270,000 logon events) the agent stays near 50%. It loses most on
  the entry and ransomware questions, where it has to pick the right few events out of hundreds
  of thousands. That is what the leads in `case_summary` (logons grouped per source address,
  account changes, tasks...) are meant to fix. The next runs will tell.
