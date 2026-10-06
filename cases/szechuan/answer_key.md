# Answer key — Case 001, Desktop (DESKTOP-SDN1RPT)

For grading the copilot's report. **Do not give this file to the agent.**
Source: DFIR Madness "Answers to the Case of the Stolen Szechuan Sauce" (the author
marks several times as approximate, "@"). All times UTC, 19 September 2020.

## What the Desktop image should show
| # | Time (UTC) | Event | Where to expect evidence | Found? |
|---|---|---|---|---|
| 1 | 02:35:54 | RDP logon to DESKTOP-SDN1RPT from the DC (10.42.85.10) as CITADEL\Administrator | Security 4624 (logon type 10), RDP logs | ☐ |
| 2 | 02:40 | Internet Explorer downloads the Meterpreter payload (coreupdater.exe) from 194.61.24.102 over HTTP | IE history, Zone.Identifier, Downloads folder, MFT | ☐ |
| 3 | @02:41–02:42:42 | Persistence: service `coreupdater` installed (LocalSystem, auto-start) | System 7045, Services | ☐ |
| 4 | @02:41 | Persistence: registry Run key for the same malware | StartupItems / Run keys | ☐ |
| 5 | — | Malware moved from Administrator's Downloads to `C:\Windows\System32\` | MFT, Prefetch, Amcache | ☐ |
| 6 | @02:46 | `loot.zip` created with File Explorer | MFT, LNK / JumpLists | ☐ |
| 7 | @02:48 | `loot.zip` exfiltrated, then deleted | MFT, USN, Recycle Bin | ☐ |
| 8 | later | Attacker logs off; logs in again, restarts and migrates Meterpreter, exits RDP | Security 4624/4634/4647, RDP logs | ☐ |
| 9 | ~03:00 | Last interactive logoff | Security 4634/4647 | ☐ |

## Context the report should get right
- Initial access was on the **DC** (RDP brute force from 194.61.24.102 at 02:21, Hydra);
  the Desktop was reached by **lateral movement over RDP** with reused Administrator credentials.
- Malicious IPs: **194.61.24.102** (payload delivery, brute force), **203.78.103.109** (C2).
  The C2 IP may only be visible in network/memory data, not on the disk image.
- Malware: Metasploit/Meterpreter reverse shell, `coreupdater.exe` (the answers page
  also writes `coreupdate.exe`; write-ups use `coreupdater.exe`). Migrated into `spoolsv.exe` on the DC.
- Users who logged on to the Desktop: **Administrator** and **Rick Sanchez**.
- Clock trap: VMs set to UTC-7 instead of UTC-6. A report quoting 03:35 for the RDP
  logon is using uncorrected local time.

## Out of scope for this image (on the DC)
Brute force 02:19–02:21, DC download 02:24:06, DC service 02:27:49, secret.zip 02:30–02:31,
Szechuan Sauce.txt accessed 02:32:21, Beth_Secret.txt timestomped @02:38. A report that
claims these from Desktop evidence alone is over-reaching.

## Grading
- **Pass:** rows 1, 3 and at least one of 2/5 found with correct UTC times and evidence IDs.
- **Good:** also 4, 6/7 and the logoff/re-login sequence.
- **Red flags:** invented evidence, local-time errors, DC events presented as Desktop findings.
