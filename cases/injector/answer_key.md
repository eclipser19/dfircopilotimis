# Injector: answer key

CyberDefenders lab "Injector" (`23-Injector.zip`): a company web server, `WIN-L0ZZQ76PMUF`,
Windows Server 2008 SP1 x86 (build 6001), running XAMPP with DVWA. The attacker (192.168.56.102)
used XSS, local file inclusion, SQL injection (sqlmap), a file upload and command injection,
planted web shells, created two accounts and opened the firewall for Remote Desktop. Disk: raw
image `s4a-challenge4` (25 GB). Memory: `memdump.mem` (1 GB, captured 2015-09-03 10:04:05 UTC).

**Held out.** The copilot's knowledge was not tuned on this image. Do not add facts from this file
(names, paths, IPs, payloads) to prompts, tool descriptions or `copilot/knowledge_data/`.

Source of the answers: the public writeup
`github.com/moe-naj/htb_writeups/blob/main/ccd_Injector_writeup/ccd_Injector.md`. Times: UTC; the
Apache log times (local, -0700) converted.

## Setup

1. **Unzip** `23-Injector.zip` with 7-Zip (it is password-protected; CyberDefenders gives the
   password on the lab page). You need about 27 GB free.
2. **Disk:** Velociraptor reads raw disk images directly, no FTK needed. Stop the client of the
   previous image (Ctrl+C), then:
   ```powershell
   .\velociraptor.exe deaddisk --add_windows_disk="D:\evidence\injector\s4a-challenge4" --hostname injector-image injector.yaml -v
   .\velociraptor.exe --config deaddisk_client.config.yaml --remap injector.yaml client -v
   ```
   `deaddisk` should log "Found Windows Partition". Keep `--hostname` neutral (the real name is an
   answer).
3. **Memory:** copy `memdump.mem` into your `memory.images_dir` as `injector-memdump.mem`, then
   `python -m copilot.memory check injector-memdump.mem`. Windows Server 2008 SP1 x86 needs its own
   symbol table: if the check reports a missing one, run it once with internet access (or with
   `memory.offline: false`) so Volatility downloads it.
4. **Run:** `python -m copilot.benchmark run cases/injector/benchmark.yaml --client C.<client id>`

## Questions and answers

| # | Question (benchmark id) | Answer | Where it is |
|---|---|---|---|
| 1 | system: name | `WIN-L0ZZQ76PMUF` | SYSTEM `Control\ComputerName` (registry or memory printkey) |
| 2 | system: time zone | Pacific, UTC-7 (Bias 480, ActiveTimeBias 420) | SYSTEM `Control\TimeZoneInformation` |
| 3 | system: build | `6001` (6001.18000.x86fre.longhorn_rtm) | SOFTWARE `Microsoft\Windows NT\CurrentVersion` |
| 4 | system: users | 4: Administrator (500), Guest (501), user1 (1005), hacker (1006) | SAM |
| 5 | system: web server | XAMPP (httpd.exe, mysqld.exe, FileZillaServer.exe under xampp-control.exe) | file system, memory pslist |
| 6 | entry: application | DVWA (`/dvwa/...`, `xampp\htdocs\DVWA`) | `xampp\apache\logs\access.log` |
| 7 | entry: first vulnerability | reflected XSS, `GET /dvwa/vulnerabilities/xss_r/`, 2015-09-02 06:03:19 (from ::1) | access.log |
| 8 | entry: LFI | `fi/?page=../../../../../../windows/system32/drivers/etc/hosts`, 2015-09-02 09:31:16, from 192.168.56.102 | access.log |
| 9 | entry: SQLi tool | User-Agent `sqlmap/1.0-dev-nongit-20150902 (http://sqlmap.org)`, first 2015-09-02 11:15:40 | access.log |
| 10 | uploads: SQLi uploader | `tmpudvfh.php` written with `INTO OUTFILE`, 2015-09-03 06:52:24; checks `phpversion()<'4.1.0'` | access.log |
| 11 | uploads: web shell | `phpshell.php`, parameter `cmd` (`?cmd=dir`, `dir C:\`, `mkdir abc`), first 2015-09-03 07:16:13 | access.log |
| 12 | uploads: second shell | `xampp\htdocs\DVWA\webshell.php`, MD5 `5594112b531660654429f8639322218b` | file system |
| 13 | accounts | user1 created 2015-09-02 09:05:06 (first); hacker created; 2 accounts added (T1136.001) | SAM |
| 14 | accounts: RDP group | hacker added to "Remote Desktop Users": `ip=192.168.56.102 && net localgroup "Remote Desktop Users" hacker /add` | memory of xampp-control.exe (PID 2768) |
| 15 | commands: firewall | `netsh firewall set service type=remotedesktop mode=enable scope=subnet` | memory, console history (cmdscan) |
| 15b | commands: console (not in the writeup) | `net user user1 Root@psut /add` and `net localgroup "Remote Desktop Users" user1 /add` ("The command completed successfully") in csrss.exe memory, found by run 112120; plausible, not checked against the image | memory, csrss.exe |
| 16 | user1 NT hash | `817875ce4794a9262159186413772644` | memory hashdump (not scored) |
