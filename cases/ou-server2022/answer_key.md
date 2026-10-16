# Compromised Windows Server 2022 (OU simulation): answer key

Dataset: "Compromised Windows Server 2022 (simulation)", Open University ORDO
(https://ordo.open.ac.uk/articles/dataset/Compromised_Windows_Server_2022_simulation_/26038642/1),
by Benjamin Donnachie, made for research on AI/ML post-breach triage. Everything in it (user names,
IP addresses) is synthetic. A small UK office network ran from September 2023 to February 2024; the
administrator enabled remote access for home working; on 12 February 2024 the server stopped
responding and showed ransomware. The disk was decrypted and imaged as E01.

**No longer blind.** Run 123740's mistakes led to generic fixes (prompt rule 11 "correlate before
claiming", the accounts and impact playbooks, Amcache times, the source IP of a logon). Facts of
this image (its IPs, accounts, file and task names) must still never go into prompts, tool
descriptions or `copilot/knowledge_data/`.

Briefing (dataset description): "Simulated UK-based small office network running from Sept 2023 to
Feb 2024. The administrator opened RDP to facilitate working from home. As part of the scenario, on
12th Feb 2024 discovered the server was no longer responding with 'Red Petya' ransomware displayed on
the screen. Forensic experts were engaged, the disk decrypted and a forensic image taken in EnCase E01
format." The iblue.team pages about it are a tool tutorial (FTK Imager, Autopsy, Plaso, AXIOM), not
a solution.

**There is no published solution.** The key was built from blind run 123740: each claim was checked
against sources that do not depend on the agent (next section). The agent's own reasoning is not
a source. Facts known from the briefing are not scored, since the agent is told them: RDP was
opened by the administrator; the ransom screen said Red Petya; discovered 12 Feb 2024.

## Building the key

Three independent sources:

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
3. **Reference lookups.** Microsoft's update history for the build number; VirusTotal for the
   SHA-1 hashes the answers report.

A fact goes into `benchmark.yaml` only when one of these confirms it.

## What the sources show

**Hayabusa** (`Windows.Hayabusa.Rules`, high and critical, flow F.DB8E3QFVPBU64): four hits.
- 2023-09-24 14:23:03 Defender real-time protection disabled (5001, logged twice). That is months
  before the intrusion, during the server's set-up. It is treated as baseline and not scored.
- 2024-02-05 23:02:22 `admin` (SID ...-2611) added to Administrators (4732).
- 2024-02-05 23:24:35 `admin` added to Domain Admins (4728).

Both group changes come from logon ID 8503211, the same session that created `admin` at
23:02:00. The rules found nothing for 6-12 February.

**Microsoft:** KB5028171 (11 July 2023) is OS build 20348.1850
(https://support.microsoft.com/kb/5028171). The server is therefore missing every cumulative update
from August 2023 (KB5029250) to January 2024 (KB5034129).

### Claims of run 123740, checked

| # | Claim | Verdict | Record(s) |
|---|---|---|---|
| 1 | First attacker logon: Administrator RDP 2024-02-05 08:52:06 after failures from 36.133.110.87 | **Wrong.** That logon's 4624 and 4648 give source 195.21.1.97, which also reconnects RDP on Thursday 8 Feb at 11:27. That looks like the administrator working from home (Monday 08:52), but it is not proven. The failures from 36.133.110.87 (workstation kali, 2024-02-04 23:37 on) never succeed in any cited record. | 8459d2d7059f3b8c, 573b86b3e4c8cfd2, 94ba92bda0965f75 |
| 1b | Administrator network logon (type 3, NTLMv2, workstation kali) from 185.229.66.183, 2024-02-05 22:55:18, after failures from 22:54:02 | **Confirmed.** This is the compromise. | 79b61576b6254c71, b58f829f79165467 |
| 1c | RDP (type 10) as admin from 31.220.85.162, 2024-02-06 20:11:00 | **Confirmed** | c8638939027e0265, d466561cef383938 |
| 2 | Account admin ("A Admin", RID 2611) created 2024-02-05 23:02:00 by Administrator (4720) | **Confirmed.** Hayabusa adds the Administrators and Domain Admins memberships, which the agent missed. | 52d0d2db79ad841e |
| 3 | SysinternalsSuite.zip in admin's Downloads, files extracted 23:13:40-23:14:40 (ZoneId=3, no HostUrl) | **Confirmed** | 72244dcd676270ef, aa586dfe810b53da, b2534e4ed22f7f7d |
| 4 | C:\Users\admin\Desktop\share.zip created 2024-02-05 23:28:30, closed 23:36:06 | **Confirmed.** Staging is shown; exfiltration is not. | 377d588ffd7243ce, c31ccf6f7a8ab5af |
| 5 | important[1].zip in admin's INetCache\IE, 2024-02-06 20:09:25 (deleted 21:00:01) | **Confirmed.** It is a browser download, so inbound, not stolen data. It probably delivered rename.exe four minutes later, but no record links the two (not scored). | edfd224ac09c0e69, 6b6ecf6aace670f4 |
| 6 | rename.exe on admin's Desktop created 2024-02-06 20:13:40; RyukReadMe.txt created 20:46:53 | **Confirmed.** The note's $SI times (2024-02-07 04:46:00, zero sub-seconds) are later than its $FN times, so they were altered. No answer noticed this (reported, not scored). | 1c6394d26df82788, a27e877ed9b8f9f6 |
| 7 | nmap, ncat, ndiff, nping "executed" 2024-02-06 21:01:08 | **Partly.** Nmap is installed in Program Files (x86)\Nmap. Amcache shows the files existed, not that they ran. | f3c63dcf40d5e972 |
| 8 | Task \Enterpries backup registered 2024-02-06 21:49:21: PsExec \\Desktop-001..006 -c -d -u admin -p letmein rename.exe, highest privileges | **Confirmed** | a9086125e56419ff |
| 8b | ...trigger start 2024-02-09 21:46:24 | **Not verified.** The parsed StartBoundary is null and the task XML is cut off in the dump (not scored). | a9086125e56419ff |
| 9 | PsExec.exe 22:14:12 (SHA-1 3e2272b9...), PsExec64.exe 22:14:14 in Amcache | **Confirmed as Amcache entries**, which are not run times | bc98799bc1e7c180, 7d1cb1f4a1abf5bb |
| 10 | rename.exe, dir.exe, cookie_exporter.exe "executed" 2024-02-07 21:00:09-10 | **Wrong reading.** The same second also holds Administrator's PsExec64.exe (21:00:11), which points to an Amcache inventory pass, not runs. cookie_exporter.exe is in Program Files (x86)\Microsoft\EdgeCore\121.0.2277.106: Edge's own program, not attacker tooling (forbidden claim). | 366a6b8239871186, 0b2b923feb556b2e, 4c232a4c50a5870f, 73b2bb3464b46adf |
| 11 | Windows Server 2022 Standard 21H2, build 20348.1850 = August 2023 | **Build confirmed, month wrong.** 1850 is July 2023 (KB5028171), so the August 2023 update is missing too. | e252078019ac0fc8, 017e09cee2e3da4b |
| 12 | SMB server (LanmanServer Start=2, Shares key), RDP (TermService), IIS installed | **SMB and RDP confirmed. IIS unproven:** CBS package keys exist on every Server 2022 install (reported, not scored). | d094db750a0e8f8b, 898cdef052ef419a, 8742d45764995ca8, 75343314224c2ba9 |
| 13 | Weak password: letmein for admin | **Confirmed** (the task's command line) | a9086125e56419ff |
| 14 | Nothing for Red Petya; no records between 10 and 13 Feb 2024 | **Consistent:** Hayabusa found nothing after 5 Feb either. There are no facts about 12 Feb. | - |

### Still open (not in the key)

- **Who created `admin`.** The 4720, 4732 and 4728 events come from Administrator's logon ID
  8503211. The kali logon at 22:55:18 got logon ID 706976421, which is a different session. Searching
  the case for `8503211` (the 4624 that opened that session) would show its source. Until then
  the key says "created by Administrator", not "by the attacker".
- **What rename.exe and dir.exe are.** Look up SHA-1 39b6d40906c7f7f080e6befa93324dddadcbd9fa
  (rename.exe, the payload the task pushes; is it Red Petya?) and
  d1c62ac62e68875085b62fa651fb17d4d7313887 (dir.exe) on VirusTotal. PsExec's
  3e2272b916da4be3c120d17490423230ab62c174 should be the signed Sysinternals PsExec 2.43.
- **Whether 195.21.1.97 is the administrator.** It is not scored either way. Only linking it to
  the password guessing is forbidden.

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

Times are UTC (the host clock was right). Host WIN-NI9FBK23SLO, domain BRANCHOFFICE
(branchoffice.example.com).

| # | Question (benchmark id) | Answer | Source |
|---|---|---|---|
| 1 | OS, patches, services (`system`) | Windows Server 2022 Standard 21H2, build 20348.1850 (July 2023, KB5028171). August 2023 to January 2024 cumulative updates missing. SMB file sharing (LanmanServer automatic, shares) and RDP. IIS not shown. | 1b-12 above, Microsoft |
| 2 | Entry and ransomware arrival (`entry`) | Administrator logon (type 3, NTLMv2, workstation kali) from 185.229.66.183 at 2024-02-05 22:55:18, after failures from 22:54:02. Separate password guessing from 36.133.110.87 (kali) from 2024-02-04 23:37. rename.exe arrived in admin's RDP session from 31.220.85.162 (logon 2024-02-06 20:11:00), written to the Desktop at 20:13:40. No exploit shown. | 1, 1b, 1c, 6 |
| 3 | Accounts (`accounts`) | Administrator used by the attacker. admin created 23:02:00 (4720), added to Administrators 23:02:22 and Domain Admins 23:24:35. admin's password is letmein. | 1b, 2, 13, Hayabusa |
| 4 | Tools and techniques (`tools`) | SysinternalsSuite.zip extracted 2024-02-05 23:13:40-23:14:40. Nmap installed. Task \Enterpries backup (2024-02-06 21:49:21) runs PsExec -c -d -u admin -p letmein rename.exe against Desktop-001 to Desktop-006. | 3, 7, 8 |
| 5 | Persistence (`persistence`) | Task \Enterpries backup (highest privileges, as admin) and the domain-admin account admin with a known password. | 2, 8 |
| 6 | Ransomware (`ransomware`) | C:\Users\admin\Desktop\rename.exe (SHA-1 39b6d409...), written 2024-02-06 20:13:40, launched with PsExec by the task and pushed to Desktop-001..006. Ransom note RyukReadMe.txt 20:46:53 ($SI times altered). | 6, 8 |
| 7 | Data (`data`) | share.zip on admin's Desktop created 2024-02-05 23:28:30 (staging). No exfiltration shown. | 4 |
| 8 | Identifiers (`identifiers`) | IPs 185.229.66.183, 36.133.110.87, 31.220.85.162; workstation kali; account admin; rename.exe SHA-1 39b6d40906c7f7f080e6befa93324dddadcbd9fa; task \Enterpries backup. | above |
| 9 | Timeline (`timeline`) | 02-05 22:55:18 compromise; 23:02:00 admin created; 23:28:30 share.zip; 02-06 20:11:00 RDP as admin; 20:13:40 rename.exe; 20:46:53 ransom note; 21:49:21 task. Nothing recorded for 12 February. | above |

### Scores

| Run | Score | Facts | Times | Forbidden | Notes |
|---|---|---|---|---|---|
| 123740 (blind, scored afterwards) | 65.5% | 28/40 | 10/18 | 2 | Entry blamed the 08:52 logon from 195.21.1.97 on the password guessing; called Edge's cookie_exporter.exe attacker tooling; missed the group changes, letmein as a weak password (accounts), 185.229.66.183 and 31.220.85.162 as identifiers, the July 2023 patch month. |
