# Answer key — Case 001, Domain controller (CITADEL-DC01)

For grading. **Do not give this file to the agent.** The machine-readable version used by the
benchmark is `benchmark.yaml`; keep the two in step.

Source: the published answers to DFIR Madness "The Case of the Stolen Szechuan Sauce" (the author
marks several times as approximate, "@"), as summarised when the desktop key was written. Every
scored row has since been seen **on the DC image itself** in the records the benchmark runs cited
(table below), so no desktop event is scored here. All times are TRUE UTC, 19 September 2020; the
DC's clock ran one hour ahead, so it records them one hour later (e.g. 02:24:06 is recorded as
03:24:06).

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

## Checked on the DC image

What the runs' cited records show (true UTC; run IDs `bench-szechuan-dc-2026101x-…`). Evidence IDs
are per run case.

| # | Seen on the DC | Record (run) |
|---|---|---|
| 1 | 4625 failures for Administrator from workstation `kali` with **no source address** (RDP with NLA) from at least 02:21:25. The published account starts them at 02:19 | 02e03b87aa88f2a4 (124015) |
| 2 | RDP authentication from 194.61.24.102 at 02:21:47, 4624 type 10 Administrator at 02:21:48 | b094eeff4039fe45, 4ada05be8ebdbd48 (124015) |
| 3 | `coreupdater.exe.2424urv.partial` renamed to `coreupdater.exe` in Administrator's Downloads at 02:24:12; `http://194.61.24.102/coreupdater.exe` in memory | d50e0bf93afc210d, 22d4f9effe606908 (124015) |
| 4, 5 | 7045 service `coreupdater` at 02:27:49, `C:\Windows\System32\coreupdater.exe`, auto start, LocalSystem; the file was moved into System32 at 02:24:50. Row 5 is confirmed, so it could be scored | 56fee2365e17e0a8, ba06dfce83ba6f8b (124015) |
| 6 | `C:\FileShare\Secret.zip` created at 02:32:39 (temporary `Secret.zip~RF77179c.TMP`), closed 02:34:18. The published "@02:30-02:31" is approximate; the fact's tolerance accepts 02:32:39 | 19bbeb14968fb306, 80ecc1e3a4f4c6ab (083214, 105830) |
| 7 | `C:\FileShare\Secret\Szechuan Sauce.txt` opened at 02:32:21 (Administrator's Recent LNK) | 134b34d4022f6558 (124015) |
| 8 | `SECRET_beth.txt` deleted to the Recycle Bin at 02:34:27; `C:\FileShare\Secret\Beth_Secret.txt` with a USN BASIC_INFO_CHANGE and no data change at 02:38:20 | 5e778ef61cca4e41 (124015), 6f9345037909adf6 (083214) |
| 9 | RDPClient 1102: the DC connected to 10.42.85.115 (DESKTOP-SDN1RPT) at 02:36:23 | dabd5ec5adf73634 (124015) |
| 10, 11 | coreupdater PID 3644 connected to 203.78.103.109:443; spoolsv.exe PID 3724 with executable private memory (malfind, MZ headers) | 7753376fa9f17a3d, 1f89b3081c383741 (124015) |
| 13, 14 | RDP reconnect from 194.61.24.102 at 02:56:04; logoff 4647 at 02:57:40 | 542732dcbb2e998a, e1c328f883b76647 (124015) |

The desktop's own events (`loot.zip`, `My Social Security Number.zip`) are forbidden claims in
`benchmark.yaml` and have not appeared in any DC run.

## Red flags
- Desktop events presented as DC findings: `loot.zip`, `My Social Security Number.zip`.
- Recorded (host clock) times given as UTC: e.g. 03:24:06 instead of 02:24:06.
- Evidence IDs that do not exist in the case database.

## Context
- Malicious IPs: 194.61.24.102 (brute force, payload server), 203.78.103.109 (C2).
- The desktop was reached from the DC over RDP with the Administrator credentials (02:35:54).
- Network: DC 10.42.85.10, desktop 10.42.85.115; domain C137.
