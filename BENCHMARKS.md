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

Minutes are wall-clock for the whole run (triage + all questions) on the developer's laptop.

### szechuan-dc

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261015-081138 | 57.9% | 7/11 | 4/8 | 4.5 | First run (the key then had 11 facts). Its misses led to the fixes in `c8859c0` and `653832e` |
| 20261015-083214 | **95.7%** | 13/13 | 9/10 | 9.0 | After those fixes |
| 20261015-103116 | (34.8%) | 8/13 | 0/10 | 15.1 | **Invalid:** the Velociraptor client was still reading the Injector image. Led to the image check (`d533b15`): a run now stops when the time-window triage finds nothing |
| 20261015-105830 | 73.9% | 11/13 | 6/10 | 12.4 | Run-to-run variance, plus the download time missing (playbook fixed in `d533b15`) |
| 20261016-124015 | 73.9% | 10/13 | 7/10 | 10.0 | First run with the correlation rule, the new record summaries, leads in `case_summary` and the larger triage (`52663f2`..`9a5a2fc`). Same score as the last valid run. Lost the brute force: the failures carry no source address (RDP with NLA), so the agent refused to tie them to the attacker's address. Missed `secret.zip` and the timestomp (it checked one file). Fixed next: failures without an address grouped by workstation name, NLA note in the entry playbook |
| *next* | | | | | With those fixes and 20 tool steps per question |

### injector

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261015-094425 | 4.8% | 1/16 | 0/5 | 4.5 | The agent spent all its tool steps without answering, and the web server's logs were never read. Fixed by the wrap-up when the steps run out (`4591811`), Apache log times and `Generic.Detection.Logs` (`ea57106`), the web-attack playbook |
| 20261015-095938 | 69.6% | 13/18 | 3/5 | 4.7 | 75.0% (14/19) once the key's matching was corrected |
| 20261015-112120 | **83.3%** | 15/19 | 5/5 | 16.2 | Commands found in memory (several words in one strings pass, `8f67eca`) |
| 20261016-130324 | 62.5% | 12/19 | 3/5 | 18.4 | Same changes. Regression on two questions. *system*: called the web server IIS (a checklist line added for OU pointed at W3SVC and `C:\inetpub`; this server has IIS installed too, but XAMPP serves the site). *entry* 0/5: spent its 15 steps on IIS logs and memory, found the Apache logs on its last step and never read them. Fixed next: no IIS pull in the system checklist, all candidate web logs in one FileFinder call (`SearchFilesGlobTable`), 20 tool steps |
| *next* | | | | | With those fixes |

### ou-server2022

Scores on the **current key (49 facts)**; the score each run got on the key of its day in brackets.

| Run | Score | Facts | Times | Min | Notes |
|---|---|---|---|---|---|
| 20261015-123740 | 52.0% (65.5% on 40 facts) | 29/49 | 10/26 | 26.5 | Blind run the key was built from. 2 forbidden claims: it pinned the administrator's own RDP logon on the guessing address, and called Edge's `cookie_exporter.exe` attacker tooling. It read Amcache times as run times |
| 20261016-085524 | 41.3% (46.6% on 40) | 23/49 | 8/26 | 110.1 | After "correlate before claiming" (`52663f2`). No forbidden claims on that key, but it hedged where the record summaries hid the logon's source IP and the task's arguments. The event-log triage was still running when the questions started. Fixed: summaries (`a7bceca`), runs wait for triage |
| 20261016-111125 | 50.7% (50.0% on 45) | 27/49 | 11/26 | 45.1 | Found the successful guessing, the RDP as Administrator, the password spreadsheet and a remote folder. Each question re-investigated everything (300-500k tokens), and the answers disagreed (one called the administrator's home address the attacker). Led to the leads in `case_summary` (`9a5a2fc`) |

## What the numbers say so far

- On the two images with published solutions the agent reaches 75-95% when the setup is right.
  Variance between identical runs is large (DC: 95.7% then 73.9%), so judge a change on at least
  two runs, never one.
- Most big drops were setup problems, not reasoning: the wrong image, triage still running,
  logs never read. The runner now catches the first two (image check, triage wait, and a warning
  under **Setup** in the scorecard).
- On a large server image (OU, ~270,000 logon events) the agent stays near 50%. It loses most on
  the entry and ransomware questions, where it has to pick the right few events out of hundreds
  of thousands. That is what the leads in `case_summary` (logons grouped per source address,
  account changes, tasks...) are meant to fix. The next runs will tell.
