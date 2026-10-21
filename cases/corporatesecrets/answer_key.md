# CorporateSecrets: answer key

CyberDefenders lab "CorporateSecrets" (Champlain College Digital Forensics Association, spring 2020
CTF): a Windows 10 workstation (build 16299) of "Fruit Inc." shared by six accounts. The download is
a logical image (`.ad1`, about 700 MB). Not an intrusion: an insider / HR case (browser searches,
documents, deleted files, a hidden Tor Browser).

**Run blind once** (20261020-141019, 60.7%: BENCHMARKS.md). Its misses then led to generic fixes
(user-folder files and their types, web searches, account usage), so it is no longer blind. Still do
not add facts from this file (names, paths, searches) to prompts, tool descriptions or
`copilot/knowledge_data/`.

Source of the answers: the public writeup
`github.com/moe-naj/htb_writeups/blob/main/ccd_CorporateSecrets_writeup/ccd_CorporateSecrets.md`.
It contradicts itself on which account owns SID ...-1003 and the VSCO search, so those are not scored
by user. Times: browser timestamps converted from the raw values in the writeup (Firefox microseconds
since 1970, Chrome microseconds since 1601).

## Setup: AD1 into Velociraptor

Velociraptor cannot open `.ad1` files, but it can read a folder that holds a Windows drive's files
(`deaddisk --add_windows_directory`). On the Windows machine with Velociraptor:

1. **Open the AD1 as a folder with FTK Imager** (free). Either
   - mount it: *File > Image Mounting*, Image File = the `.ad1`, Mount Method *File System / Read Only*,
     pick a drive letter, *Mount*; or
   - export it: *File > Add Evidence Item > Image File* = the `.ad1`, right-click the top folder in
     the Evidence Tree, *Export Files*, to e.g. `D:\evidence\corpsec\`;
   - or, without FTK, extract it with AD1-tools (github.com/al3ks1s/AD1-tools, Linux, so in WSL):
     install the `.deb` from its releases page, then
     `ad1extract -i /mnt/c/evidence/CorporateSecrets.ad1 -d /mnt/c/evidence/corpsec -m`
     (`-m` keeps the original timestamps).
2. **Find the folder that contains `Windows` and `Users`** (for example `F:\...\[root]`). That
   folder is the "C: drive" of the image.
3. **Make the remapping and start the client** (stop the client of the previous image first, Ctrl+C):
   ```powershell
   .\velociraptor.exe deaddisk --add_windows_directory="F:\...\[root]" --hostname corpsec-image deaddisk-corpsec.yaml -v
   .\velociraptor.exe --config deaddisk_client.config.yaml --remap deaddisk-corpsec.yaml client -v
   ```
   Keep `--hostname` neutral: the agent sees it, and the real name is one of the answers. With the
   same client config the client keeps its client ID (`C.xxxx`), now reading this image.
4. Check it: `python -m copilot.selftest` (or collect `Windows.Sys.Users` in the GUI: six users).

What a folder image cannot give: the NTFS journal (USN), deleted MFT records and unallocated space.
Registry, event logs, Prefetch, LNK, Recycle Bin and browser databases are read normally.

## Questions and answers

| # | Question (benchmark id) | Answer | Where it is |
|---|---|---|---|
| 1 | system: computer name | `DESKTOP-3A4NLVQ` | SYSTEM `ControlSet001\Control\ComputerName\ComputerName` |
| 2 | system: Windows build | `16299` (Windows 10 1709) | SOFTWARE `Microsoft\Windows NT\CurrentVersion` CurrentBuild |
| 3 | system: domain | `fruitinc.xyz` | SYSTEM `Services\Tcpip\Parameters` DhcpDomain |
| 4 | system: last IP | `192.168.2.242` | SYSTEM `Tcpip\Parameters\Interfaces\{f2329ece-...}` DhcpIPAddress |
| 5 | system: users | admin, hansel.apricot, jim.tomato, miriam.grapes, suzy.strawberry, tim.apple (6) | SOFTWARE ProfileList |
| 6 | accounts: last user | `jim.tomato` | SOFTWARE `Winlogon` LastUsedUsername (DefaultUserName is miriam.grapes) |
| 7 | accounts: admin logons | 10 | SAM, RID 1001 login count |
| 8 | web: flirting | tim.apple, Firefox: "is it ok to flirt with my secretary", 2020-04-09 20:45:07 | places.sqlite |
| 9 | web: firing | tim.apple, Chrome: "hhoww ddoo i niicceelyy fiirre mmy sttiinkyy eemmpplooyye", 2020-04-09 20:36:29 | Chrome History |
| 10 | web: hacking | jim.tomato, Chrome: YouTube `watch?v=Y-CsIqTFEyY` "How To Hack Into a Computer", 2020-04-12 04:39:33 | Chrome History |
| 11 | web: VSCO | Firefox: "what kind of phones do vsco girls enjoy", 2020-04-11 20:00:09 (miriam.grapes per the challenge question) | places.sqlite |
| 12 | privacy_tools | Tor Browser in `C:\Program1`, used by jim.tomato (Start Tor Browser.lnk), launched twice (RecentApps, last 2020-04-16 04:52:28) | file system, NTUSER RecentApps |
| 13 | documents: last .docx | 2020-04-11 23:23:36 (jim.tomato `RecentDocs\.docx` LastWrite; CompanySecrets.docx, Document1.docx, Untitled 1.docx) | NTUSER RecentDocs |
| 14 | documents: CEO plans | `C:\Users\tim.apple\Documents\secret.odt`: 4 plans incl. "Fire Jim Tomato" | file content (not scored) |
| 15 | installs | miriam.grapes: LibreCAD-Installer-2.1.3.exe (Downloads, ran: Prefetch) | file system, Prefetch |
| 16 | archives | 7zG.exe last ran 2020-04-12 02:32:09 (also 04-12 01:29:05, 04-11 23:23:06, 23:20:36, 23:17:34); `Users\miriam.grapes\Pictures\vegetable` is a 7z archive without extension | Prefetch, file magic |
| 17 | deleted | `$RGETALS.jpg` (dog photo, originally `Users\hansel.apricot\Downloads\Chinook-On-White-03.jpg`: the only file in that bin) in hansel.apricot's bin (SID ...-1005); `$RQ1FSDY.docx` "Fruit inc. company secrets" (4th: "Customer data is not stored securely") in the bin of SID ...-1003 | Recycle Bin |

Left out of the benchmark (CTF puzzles rather than investigation questions, or outside the
copilot's reach): CRC64 of fruit_apricot.jpg (`ED865AA6DFD756BF`), size of strawberry.jpg (72448),
CPU architecture (AMD64), machine SID (`S-1-5-21-2446097003-76624807-2828106174`), suzy.strawberry RID
(1004), browsers present (5), background image time (2020-04-05 03:49), PNG hidden in samplePhone.jpg
(SHA-1 `537fe19a560ba3578d2f9095dc2f591489ff2cde`), MFT entries (219904), LSN of fruit_Assortment.jpg
(1276820064), Firefox prefetch with most runs (`FIREFOX.EXE-A606B53C.pf`, 21), admin's startup item
(OneDrive), user with most taskbar pins (admin), Slack threat ("kneecaps").
