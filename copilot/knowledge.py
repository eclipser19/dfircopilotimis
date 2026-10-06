"""
Artifact reference: where each artifact's data lives, what it proves, and how to use it.

Used for the report's "Artifacts, locations & meanings" section (so that part is never
written by the LLM) and shown to the agent by describe_artifact. Entries are matched by
artifact-name pattern, first match wins; keep the most specific patterns first.
"""
import fnmatch

ARTIFACT_INFO = [
    ("Windows.EventLogs.RDPAuth*", {
        "what": "Remote Desktop and logon events",
        "location": r"C:\Windows\System32\winevt\Logs\Security.evtx (4624/4625/4634/4647/4778/4779), "
                    r"TerminalServices-RemoteConnectionManager (1149), TerminalServices-LocalSessionManager (21-25)",
        "meaning": "Who logged on interactively or over RDP, from which IP/host, when, and when they left.",
    }),
    ("Windows.EventLogs.PowershellScriptblock*", {
        "what": "PowerShell script block logging (4104)",
        "location": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
        "meaning": "The PowerShell code that actually ran, including decoded/deobfuscated stages.",
    }),
    ("Windows.EventLogs.EvtxHunter*", {
        "what": "Search across all Windows event logs",
        "location": r"C:\Windows\System32\winevt\Logs\*.evtx",
        "meaning": "Any event by ID or content: e.g. 7045 service installed, 4688 process created, "
                   "4698 task created, 1102/104 logs cleared, 4104 PowerShell code.",
        "tips": ["IdRegex matches the event ID; anchor it (e.g. ^(7045|4624)$) to avoid matching 47045.",
                 "IocRegex matches event content; use '.' to keep every event of the selected IDs."],
    }),
    ("Windows.EventLogs.*", {
        "what": "Windows event log records",
        "location": r"C:\Windows\System32\winevt\Logs\*.evtx",
        "meaning": "System, security and application activity recorded by Windows.",
    }),
    ("Windows.Timeline.Prefetch*", {
        "what": "Prefetch execution history",
        "location": r"C:\Windows\Prefetch\*.pf",
        "meaning": "A program ran: executable name, run count and up to 8 last run times (Windows 10). "
                   "Proves execution even if the binary was deleted.",
    }),
    ("Windows.Forensics.Prefetch*", {
        "what": "Prefetch files (parsed)",
        "location": r"C:\Windows\Prefetch\*.pf",
        "meaning": "Program execution, run count, last run times and files loaded by the program.",
    }),
    ("Windows.NTFS.MFT*", {
        "what": "NTFS Master File Table",
        "location": r"C:\$MFT",
        "meaning": "Which files exist(ed), their full paths, sizes and MACB times ($STANDARD_INFORMATION 0x10 "
                   "and $FILE_NAME 0x30). Entries of deleted files can survive until reused.",
        "tips": ["FileRegex matches the file NAME only; to search a folder use PathRegex.",
                 "DateAfter/DateBefore filter on timestamps: when hunting a known file name, drop them so "
                 "older or timestomped entries are not excluded.",
                 "0x10 times can be timestomped; compare them with the 0x30 ($FILE_NAME) times."],
    }),
    ("*Usn*", {
        "what": "NTFS USN change journal",
        "location": r"C:\$Extend\$UsnJrnl:$J",
        "meaning": "File creations, renames and deletions with times, even after the file is gone: the best "
                   "source to prove a file (e.g. an archive) was created and then deleted.",
    }),
    ("Windows.Sys.StartupItems*", {
        "what": "Autostart entries",
        "location": r"HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run, RunOnce; Startup folders",
        "meaning": "Programs or commands started at every logon: a common persistence mechanism. "
                   "Entries carry no timestamp of their own.",
    }),
    ("Windows.System.TaskScheduler*", {
        "what": "Scheduled tasks",
        "location": r"C:\Windows\System32\Tasks\**",
        "meaning": "Tasks that run programs on a schedule or trigger: persistence and execution.",
    }),
    ("Windows.System.Services*", {
        "what": "Installed services (live system only)",
        "location": "WMI on a running system",
        "meaning": "Does not work on disk images; use event 7045 or the SYSTEM hive instead.",
    }),
    ("Windows.System.Powershell.PSReadline*", {
        "what": "PowerShell console history",
        "location": r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "meaning": "Commands typed in interactive PowerShell consoles. No timestamps.",
    }),
    ("Windows.Registry.*", {
        "what": "Registry data",
        "location": r"C:\Windows\System32\config\{SYSTEM,SOFTWARE,SAM,SECURITY}, C:\Users\*\NTUSER.DAT",
        "meaning": "System and user configuration, persistence keys and user activity traces.",
    }),
    ("Windows.Applications.*", {
        "what": "Application artifacts (browsers etc.)",
        "location": "Per-application profile folders under C:\\Users\\*",
        "meaning": "Browsing and download history. Note: several of these artifacts depend on live-only "
                   "functions (e.g. lookupSID) and return nothing from a disk image.",
    }),
    ("Generic.Client.Info*", {
        "what": "System information",
        "location": "Collected by Velociraptor from the image",
        "meaning": "Hostname, OS version, users. Timestamps in BasicInformation describe the collection, "
                   "not the incident.",
    }),
    ("Linux.Sys.Users*", {
        "what": "Local users", "location": "/etc/passwd", "meaning": "Accounts present on the system.",
    }),
    ("Linux.Syslog.SSHLogin*", {
        "what": "SSH logins", "location": "/var/log/auth.log, /var/log/secure",
        "meaning": "Who logged in over SSH, from where and when.",
    }),
    ("Linux.Forensics.Journal*", {
        "what": "systemd journal", "location": "/var/log/journal",
        "meaning": "System and service log messages.",
    }),
]

UNKNOWN = {"what": "Velociraptor artifact", "location": "—", "meaning": "See the artifact's description."}


def artifact_info(source: str) -> dict:
    artifact = source.split("/", 1)[0]
    for pattern, info in ARTIFACT_INFO:
        if fnmatch.fnmatchcase(artifact, pattern):
            return info
    return UNKNOWN
