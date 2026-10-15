# Compromised Windows Server 2022 (OU simulation): answer key

Dataset: "Compromised Windows Server 2022 (simulation)", Open University ORDO
(https://ordo.open.ac.uk/articles/dataset/Compromised_Windows_Server_2022_simulation_/26038642/1),
by Benjamin Donnachie, made for research on AI/ML post-breach triage. Everything in it (user names,
IP addresses) is synthetic. A small UK office network ran from September 2023 to February 2024; the
administrator enabled remote access for home working; on 12 February 2024 the server stopped
responding and showed ransomware. The disk was decrypted and imaged as E01.

**Held out.** The copilot's knowledge is not tuned on this image. Do not add facts from it to
prompts, tool descriptions or `copilot/knowledge_data/`.

Briefing (dataset description): "Simulated UK-based small office network running from Sept 2023 to
Feb 2024. The administrator opened RDP to facilitate working from home. As part of the scenario, on
12th Feb 2024 discovered the server was no longer responding with 'Red Petya' ransomware displayed on
the screen. Forensic experts were engaged, the disk decrypted and a forensic image taken in EnCase E01
format." The iblue.team pages about it are a tool tutorial (FTK Imager, Autopsy, Plaso, AXIOM), not
a solution.

**No key yet: there is no published solution.** Facts known from the briefing only (not scored,
since the agent is told them): RDP was opened by the administrator; the ransom screen said Red Petya;
discovered 12 Feb 2024.

## Building the key

The key must not come from the agent's own reasoning. Three independent sources:

1. **The raw records the answers cite.** `python -m copilot.benchmark evidence benchmark_results/<run>.json`
   writes `<run>.evidence.md`: for every evidence ID an answer cites, the record exactly as
   Velociraptor returned it, with its times. A claim becomes a fact only if its record shows it.
2. **Detection rules, no agent involved.** In the Velociraptor GUI as an admin: Server Artifacts ->
   collect `Server.Import.Extras` with only the "The Velociraptor Sigma Project" row in Details
   (the server needs internet), then collect the imported Hayabusa / Sigma event-log artifact
   (search "Hayabusa" in the artifact list) on this image's client, levels high and critical
   first. It runs inside Velociraptor (no external program), so it works on a dead disk. These
   rules need permissions the copilot's investigator role does not have. Export the hits (CSV).
   This is the only source for things the agent never mentioned.
3. **Hash lookups.** The SHA-1 hashes the answers report (rename.exe, PsExec) can be checked on
   VirusTotal: an official Sysinternals PsExec hash, and what rename.exe really is.

A fact goes into `benchmark.yaml` only when one of these confirms it; its source is noted below.

## Claims from run 123740 to check

The answers contradict each other in places; the raw records decide.

| # | Claim | Answers | Check |
|---|---|---|---|
| 1 | First attacker logon: Administrator RDP (type 10) 2024-02-05 08:52:06 after failures from 36.133.110.87 from 08:45 | entry | records 8459d2d7059f3b8c, b773bf7a3e8a32cf |
| 1b | ...or Administrator network logon (type 3) 2024-02-05 22:55:18 from 185.229.66.183 (workstation kali) after failures from 22:54:02 | data, timeline | records 79b61576b6254c71, b58f829f79165467 |
| 1c | RDP (type 10) as admin from 31.220.85.162, 2024-02-06 20:11:00 | timeline | c8638939027e0265 |
| 1d | Failed logons from 36.133.110.87 from 2024-02-04 23:37; RDP reconnects from 195.21.1.97 on 2024-02-08 | identifiers | 0080192f8ccddf50, 94ba92bda0965f75 |
| 2 | Account admin created 2024-02-05 23:02 by Administrator (4720), domain BRANCHOFFICE | accounts | 52d0d2db79ad841e |
| 3 | SysinternalsSuite.zip extracted to C:\Users\admin\Downloads around 2024-02-05 23:13-23:14 (ZoneId=3, no HostUrl) | entry, tools | 72244dcd676270ef, aa586dfe810b53da |
| 4 | C:\Users\admin\Desktop\share.zip created 2024-02-05 23:28:30, closed 23:36:06 | data | 377d588ffd7243ce, c31ccf6f7a8ab5af |
| 5 | important[1].zip in admin's INetCache 2024-02-06 20:09:25 | data | edfd224ac09c0e69 |
| 6 | rename.exe on admin's Desktop created 2024-02-06 20:13:40; RyukReadMe.txt created 20:46:53 | ransomware | 1c6394d26df82788, a27e877ed9b8f9f6 |
| 7 | nmap, ncat, ndiff, nping in Amcache 2024-02-06 21:01:08 | tools | f3c63dcf40d5e972, 06f3fa5e8fb221d4 |
| 8 | Scheduled task \Enterpries backup registered 2024-02-06 21:49:21: PsExec \\Desktop-001..006 -u admin -p letmein -c -d rename.exe, start 2024-02-09 21:46:24 | tools, persistence | a9086125e56419ff |
| 9 | PsExec.exe 2024-02-06 22:14:12 (SHA-1 3e2272b9...), PsExec64.exe 22:14:14 (0098c79e...) in Amcache | tools | bc98799bc1e7c180, 7d1cb1f4a1abf5bb |
| 10 | rename.exe (SHA-1 39b6d40906c7f7f080e6befa93324dddadcbd9fa), cookie_exporter.exe, dir.exe in Amcache 2024-02-07 21:00:09-10 | tools, ransomware | 366a6b8239871186, 4c232a4c50a5870f |
| 11 | Windows Server 2022 Standard 21H2, build 20348.1850 (UBR 1850: the agent says August 2023; check against Microsoft's release list, it may be July 2023 KB5028171), later cumulative updates missing | system | e252078019ac0fc8, 017e09cee2e3da4b |
| 12 | Services: SMB server (LanmanServer automatic, shares key), RDP (TermService), IIS components installed | system | d094db750a0e8f8b, 8742d45764995ca8 |
| 13 | Weak password: letmein for admin (in the task command line) | tools, persistence | a9086125e56419ff |
| 14 | Nothing found for Red Petya, and no records between 10 and 13 Feb 2024 | ransomware, timeline | Sigma hits / the image itself |

## Setup

1. Download the E01 from ORDO and keep it **outside OneDrive** (e.g. `C:\evidence\ou-server2022\`).
2. Stop the Velociraptor client of the previous image (Ctrl+C), then:
   ```powershell
   .\velociraptor.exe deaddisk --add_windows_disk="C:\evidence\ou-server2022\<image>.E01" --hostname ou-image ou.yaml -v
   .\velociraptor.exe --config deaddisk_client.config.yaml --remap ou.yaml client -v
   ```
   `deaddisk` should log "Found Windows Partition". Keep `--hostname` neutral.
3. Check: collect `Windows.EventLogs.RDPAuth` in the GUI; it should return rows from 2023-2024.
4. Run: `python -m copilot.benchmark run cases/ou-server2022/benchmark.yaml --client C.<client id>`

## Questions and answers

| # | Question (benchmark id) | Answer | Source |
|---|---|---|---|
| | (to be filled) | | |
