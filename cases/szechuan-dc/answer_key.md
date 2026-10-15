# Answer key — Case 001, Domain controller (CITADEL-DC01)

For grading. **Do not give this file to the agent.** The machine-readable version used by the
benchmark is `benchmark.yaml`; keep the two in step.

Source: the published answers to DFIR Madness "The Case of the Stolen Szechuan Sauce" (the author
marks several times as approximate, "@"), as summarised when the desktop key was written. Not yet
checked against the answers page line by line: paste it in and correct anything that differs.
All times are TRUE UTC, 19 September 2020; the DC's clock ran one hour ahead, so it records
them one hour later (e.g. 02:24:06 is recorded as 03:24:06).

## What the DC image should show
| # | Time (UTC) | Event | Where to expect evidence | Scored |
|---|---|---|---|---|
| 1 | 02:19–02:21 | RDP password guessing (Hydra) from 194.61.24.102 | Security 4625 burst, RDP logs | yes |
| 2 | @02:21 | Successful RDP logon as Administrator from 194.61.24.102 | Security 4624 type 10, 1149, LocalSessionManager 21 | yes |
| 3 | 02:24:06 | coreupdater.exe downloaded from 194.61.24.102 | Browser history / cache, Zone.Identifier, USN, MFT | yes |
| 4 | 02:27:49 | Service `coreupdater` installed | System 7045 | yes |
| 5 | — | Service binary in `C:\Windows\System32` | 7045 ImagePath, MFT | no (path unconfirmed) |
| 6 | @02:30–02:31 | `secret.zip` created | USN, MFT, LNK | yes |
| 7 | 02:32:21 | `Szechuan Sauce.txt` accessed | LNK / JumpLists, MFT access time, Shellbags | yes |
| 8 | @02:38 | `Beth_Secret.txt` timestomped | MFT: $SI (0x10) times differ from $FN (0x30) | yes |
| 9 | 02:35:54 | RDP from the DC to DESKTOP-SDN1RPT (10.42.85.115) | Prefetch mstsc.exe, 4648, RDPClient 1024, Terminal Server Client MRU | yes |
| 10 | memory | C2 connection to 203.78.103.109 | netscan, memsearch | yes |
| 11 | memory | Backdoor inside spoolsv.exe (Meterpreter migrated) | malfind, netscan owner, memsearch | yes |
| 12 | memory | Identified as Meterpreter | malfind / strings, AV | no (hard to prove) |
| 13 | 02:56:04 | Attacker comes back over RDP from 194.61.24.102 after a disconnect at 02:52:46 | 1149, LocalSessionManager 21/25, 4624 | yes |
| 14 | 02:57:40 | Attacker's last RDP session logs off (published: ~03:00) | 4647, LocalSessionManager 23 | yes |
| 15 | later | Server restarted during the attack (published account) | System 1074/6005/6006 | no (unconfirmed) |

Rows 13-14: times from the events the copilot cited in run bench-szechuan-dc-20261015-081138; they fit
the published account (the attacker logs on again; last logoff around 03:00). Check them if in doubt.

## Red flags
- Desktop events presented as DC findings: `loot.zip`, `My Social Security Number.zip`.
- Recorded (host clock) times given as UTC: e.g. 03:24:06 instead of 02:24:06.
- Evidence IDs that do not exist in the case database.

## Context
- Malicious IPs: 194.61.24.102 (brute force, payload server), 203.78.103.109 (C2).
- The desktop was reached from the DC over RDP with the Administrator credentials (02:35:54).
- Network: DC 10.42.85.10, desktop 10.42.85.115; domain C137.
