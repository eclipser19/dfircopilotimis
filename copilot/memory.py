"""
Memory analysis with Volatility 3, against the case's memory image.

Server (server.yaml, see copilot/settings.py):
    memory:
      images_dir: D:\\dfir\\memory     # memory images the copilot may open
      symbols_dir: D:\\dfir\\symbols   # Windows symbol tables: windows.zip and/or downloaded tables
      offline: true                    # never download symbols (Volatility's --offline)
      timeout: 3600                    # seconds per plugin run
      yara_dir: D:\\dfir\\yara           # optional: YARA rule files (.yar) the agent may scan memory with

Case (case.yaml):
    memory:
      image: DESKTOP-SDN1RPT.mem       # a file in images_dir (chosen in the app's case settings)
      os: windows                      # windows | linux: picks the default triage plugins
      collect: [windows.pslist, ...]   # optional: the memory triage list

Volatility runs as a separate process with the copilot's own Python (pip install volatility3),
rendering JSON. Its rows go into the case database like collected artifacts (source
"Memory.<plugin>"), so the timeline, search, findings and report include them.

Only the plugins in PLUGINS can run, with only the options listed there: nothing that dumps
files, writes outside the case, or reads anything but an image in images_dir (and rule files
in yara_dir).

Searching memory: `strings` reads the image file itself for a text (no Volatility, also freed
memory, but no process); windows.memsearch finds it per process, or scans with a rule file from
yara_dir (rules need `pip install yara-x` or yara-python next to Volatility). windows.memsearch
is the copilot's own Volatility plugin (vol_plugins/dfir_memsearch.py, loaded with -p).
"""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

from copilot import settings
from copilot.case_config import case_config
from copilot.database import case_db

# The copilot's own Volatility plugins (Volatility's -p option).
PLUGIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vol_plugins")
# Runs Volatility's command line with this Python (the `vol` script is often not on PATH).
BOOT = "import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; main()"
IMAGE_EXTENSIONS = {".mem", ".raw", ".vmem", ".dmp", ".lime", ".bin", ".img", ".dd", ".mddramimage",
                    ".core", ".elf", ".vmsn", ".vmss", ".hpak", ".crash"}


class MemoryAnalysisError(Exception):
    """Memory analysis could not run; the message is safe to show to the agent or user."""


class Plugin:
    def __init__(self, names, about, options=(), heavy=False, needs_one_of=(), post=None, requires="",
                 yara_string=False):
        self.names = names            # full Volatility names, newest first (renamed between versions)
        self.about = about
        self.options = set(options)   # pid | key | recurse | contains | text | words | rules
        self.heavy = heavy            # the agent must narrow it (pid / key / contains)
        self.needs_one_of = set(needs_one_of)   # a search: one of these options is required
        self.post = post              # rows -> rows, after Volatility (e.g. decode matched bytes)
        self.requires = requires      # what to install when the installed Volatility lacks it
        self.yara_string = yara_string    # Volatility's YARA plugins: text goes in as a --yara-string rule

    @property
    def searches(self) -> bool:
        return bool(self.needs_one_of)


YARA_INSTALL = ("YARA for Python is not installed next to Volatility: run 'pip install yara-x' "
                "(or yara-python) with the copilot's Python, then restart the copilot.")
YARA_PLUGIN = "yarascan.YaraScan"      # listed by Volatility only when YARA for Python is installed


def _printable(data: bytes) -> tuple:
    """(text, encoding) for matched bytes: UTF-16 when every second byte is zero."""
    if len(data) >= 4 and not any(data[1::2]):
        text, encoding = data[0::2].decode("latin-1"), "UTF-16"
    else:
        text, encoding = data.decode("latin-1"), "ASCII"
    return "".join(c if " " <= c <= "~" else "." for c in text), encoding


def _yara_hits(rows: list, options: dict) -> list:
    """
    One row per process and matched text (Volatility reports every offset): the matched bytes
    (hex) become readable text, with how often and where first.
    """
    grouped = {}
    for row in rows:
        try:
            data = bytes.fromhex(str(row.get("Value") or ""))
        except ValueError:
            data = str(row.get("Value") or "").encode()
        match, encoding = _printable(data)
        rule = "" if options.get("text") else row.get("Rule") or ""     # a text search's rule is generated
        key = (row.get("PID"), rule, match)
        if key in grouped:
            grouped[key]["Hits"] += 1
            continue
        hit = {k: v for k, v in row.items() if k not in ("Value", "Component", "Rule", "Offset", "ImageFileName")}
        if "ImageFileName" in row:
            hit["Process"] = row["ImageFileName"]
        hit.update(Match=match, Encoding=encoding, Hits=1, FirstOffset=row.get("Offset"))
        if rule:
            hit["Rule"] = rule
        grouped[key] = hit
    return list(grouped.values())


# Short name -> plugin. Volatility accepts the full names on every 2.x version.
PLUGINS = {
    # --- Windows: processes
    "windows.info": Plugin(["windows.info.Info"], "OS build, kernel and the capture's system time"),
    "windows.pslist": Plugin(["windows.pslist.PsList"],
                             "Running processes from the kernel list: PID, PPID, name, create/exit time",
                             ["pid", "contains"]),
    "windows.psscan": Plugin(["windows.psscan.PsScan"],
                             "Processes found by scanning memory, including exited and unlinked (hidden) ones; "
                             "compare with pslist", ["pid", "contains"]),
    "windows.pstree": Plugin(["windows.pstree.PsTree"], "Process tree: which process started which",
                             ["pid", "contains"]),
    "windows.psxview": Plugin(["windows.malware.psxview.PsXView", "windows.psxview.PsXView"],
                              "Process visibility across listing methods (hidden process detection)", ["contains"]),
    "windows.cmdline": Plugin(["windows.cmdline.CmdLine"], "Command line of each process", ["pid", "contains"]),
    "windows.envars": Plugin(["windows.envars.Envars"], "Environment variables per process",
                             ["pid", "contains"], heavy=True),
    "windows.getsids": Plugin(["windows.getsids.GetSIDs"], "Account and group SIDs of each process' token",
                              ["pid", "contains"]),
    "windows.privileges": Plugin(["windows.privileges.Privs"], "Token privileges per process (e.g. SeDebugPrivilege)",
                                 ["pid", "contains"], heavy=True),
    "windows.sessions": Plugin(["windows.sessions.Sessions"], "Logon sessions and the processes in them",
                               ["pid", "contains"]),
    "windows.dlllist": Plugin(["windows.dlllist.DllList"], "DLLs loaded by each process (path, load time)",
                              ["pid", "contains"], heavy=True),
    "windows.ldrmodules": Plugin(["windows.malware.ldrmodules.LdrModules", "windows.ldrmodules.LdrModules"],
                                 "DLLs missing from the loader lists (unlinked or injected modules)",
                                 ["pid", "contains"], heavy=True),
    "windows.handles": Plugin(["windows.handles.Handles"], "Open handles (files, registry keys, mutexes) per process",
                              ["pid", "contains"], heavy=True),
    "windows.vadinfo": Plugin(["windows.vadinfo.VadInfo"], "Virtual memory regions of a process and their protection",
                              ["pid", "contains"], heavy=True),
    # --- Searching memory
    "strings": Plugin([], "Searches the image file itself for a text (IP, domain, URL, file name), ASCII and "
                          "UTF-16, with the text around it; or for several words at once (words), e.g. command "
                          "names, each hit with the rest of its line. Finds leftovers in freed memory too; does "
                          "not say which process (then use windows.memsearch). Fast, needs no symbols.",
                      ["text", "words"], needs_one_of=["text", "words"]),
    "windows.memsearch": Plugin(["dfir_memsearch.MemSearch"],
                                "Searches each running process's memory: which processes hold a text (text), "
                                "with the text around it, or match a YARA rule file from the server (rules)",
                                ["pid", "text", "rules"], needs_one_of=["text", "rules"]),
    # --- Windows: network
    "windows.netscan": Plugin(["windows.netscan.NetScan"],
                              "Network connections and listening sockets, also closed ones: owner process, "
                              "PID, local/remote address, state, creation time", ["contains"]),
    "windows.netstat": Plugin(["windows.netstat.NetStat"], "Active connections from the kernel's lists",
                              ["contains"]),
    # --- Windows: malware
    "windows.malfind": Plugin(["windows.malware.malfind.Malfind", "windows.malfind.Malfind"],
                              "Memory regions with signs of code injection (executable private memory, PE headers)",
                              ["pid", "contains"]),
    "windows.hollowprocesses": Plugin(["windows.malware.hollowprocesses.HollowProcesses",
                                       "windows.hollowprocesses.HollowProcesses"],
                                      "Process hollowing: image base not matching the mapped file", ["pid"]),
    "windows.processghosting": Plugin(["windows.malware.processghosting.ProcessGhosting",
                                       "windows.processghosting.ProcessGhosting"],
                                      "Processes started from deleted or pending-delete files"),
    "windows.suspicious_threads": Plugin(["windows.malware.suspicious_threads.SuspiciousThreads",
                                          "windows.suspicious_threads.SuspiciousThreads"],
                                         "Threads starting in unbacked or unusual memory", ["pid"]),
    "windows.svcscan": Plugin(["windows.svcscan.SvcScan"], "Services: name, binary, state, start type",
                              ["contains"]),
    "windows.svcdiff": Plugin(["windows.malware.svcdiff.SvcDiff", "windows.svcdiff.SvcDiff"],
                              "Services hidden from the service control manager's list"),
    "windows.mutantscan": Plugin(["windows.mutantscan.MutantScan"], "Mutexes (malware often uses fixed names)",
                                 ["contains"]),
    "windows.filescan": Plugin(["windows.filescan.FileScan"], "File objects in memory (paths of open/recent files)",
                               ["contains"], heavy=True),
    "windows.cmdscan": Plugin(["windows.cmdscan.CmdScan"], "Command history of cmd.exe consoles"),
    "windows.consoles": Plugin(["windows.consoles.Consoles"], "Console input and output buffers (typed commands "
                                                              "and what they printed)"),
    # --- Windows: registry in memory
    "windows.registry.hivelist": Plugin(["windows.registry.hivelist.HiveList"], "Registry hives loaded in memory"),
    "windows.registry.printkey": Plugin(["windows.registry.printkey.PrintKey"],
                                        "Values of a registry key from memory, e.g. "
                                        "'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                                        ["key", "recurse", "contains"], heavy=True),
    "windows.registry.userassist": Plugin(["windows.registry.userassist.UserAssist"],
                                          "UserAssist: GUI programs a user ran, with counts and last run time"),
    "windows.registry.amcache": Plugin(["windows.registry.amcache.Amcache"], "Amcache entries from memory",
                                       ["contains"]),
    "windows.registry.scheduled_tasks": Plugin(["windows.registry.scheduled_tasks.ScheduledTasks"],
                                               "Scheduled tasks from the registry in memory"),
    "windows.shimcachemem": Plugin(["windows.shimcachemem.ShimcacheMem"], "ShimCache entries still in memory",
                                   ["contains"]),
    # --- Windows: kernel / rootkits
    "windows.modules": Plugin(["windows.modules.Modules"], "Loaded kernel drivers", ["contains"]),
    "windows.driverscan": Plugin(["windows.driverscan.DriverScan"], "Driver objects found by scanning (hidden drivers)",
                                 ["contains"]),
    "windows.callbacks": Plugin(["windows.callbacks.Callbacks"], "Kernel callbacks (rootkits register these)"),
    "windows.ssdt": Plugin(["windows.ssdt.SSDT"], "System call table (hooks point outside the kernel)",
                           ["contains"]),
    # --- Linux (needs a symbol table built for the exact kernel)
    "linux.pslist": Plugin(["linux.pslist.PsList"], "Processes", ["pid", "contains"]),
    "linux.psaux": Plugin(["linux.psaux.PsAux"], "Processes with their full command line", ["pid", "contains"]),
    "linux.pstree": Plugin(["linux.pstree.PsTree"], "Process tree", ["pid"]),
    "linux.bash": Plugin(["linux.bash.Bash"], "Bash command history recovered from memory", ["pid", "contains"]),
    "linux.sockstat": Plugin(["linux.sockstat.Sockstat"], "Network sockets per process", ["pid", "contains"]),
    "linux.lsof": Plugin(["linux.lsof.Lsof"], "Open files per process", ["pid", "contains"], heavy=True),
    "linux.malfind": Plugin(["linux.malfind.Malfind"], "Memory regions with signs of code injection", ["pid"]),
    "linux.envars": Plugin(["linux.envars.Envars"], "Environment variables per process", ["pid", "contains"],
                           heavy=True),
    "linux.lsmod": Plugin(["linux.lsmod.Lsmod"], "Loaded kernel modules"),
    "linux.boottime": Plugin(["linux.boottime.Boottime"], "When the system booted"),
    "linux.vmayarascan": Plugin(["linux.vmayarascan.VmaYaraScan"],
                                "YARA scan of each process's memory for a text or with a rule file",
                                ["pid", "text", "rules"], needs_one_of=["text", "rules"], post=_yara_hits,
                                requires=YARA_INSTALL, yara_string=True),
}

# Raw search of the image file (the `strings` plugin).
MAX_STRING_HITS = 5000
_CHUNK = 64 * 1024 * 1024
_BEFORE, _AFTER = 60, 100

TRIAGE = {
    "windows": ["windows.info", "windows.pslist", "windows.psscan", "windows.pstree", "windows.cmdline",
                "windows.netscan", "windows.svcscan", "windows.malfind"],
    "linux": ["linux.boottime", "linux.pslist", "linux.psaux", "linux.bash", "linux.sockstat", "linux.malfind"],
}


# ---------------------------------------------------------------- server settings
def images_dir() -> str:
    path = settings.get("memory", "images_dir", "DFIR_MEMORY_DIR", "")
    return os.path.abspath(str(path)) if path else ""


def symbols_dir() -> str:
    path = settings.get("memory", "symbols_dir", "DFIR_VOL_SYMBOLS", "")
    return os.path.abspath(str(path)) if path else ""


def symbols_problem() -> str:
    """Why memory.symbols_dir can't be used as set ("" = fine, or not set). Volatility expects the
    folder that holds windows\\<pdb name>\\<id>.json.xz (and windows.zip), not a file or a sub-folder."""
    path = symbols_dir()
    if not path:
        return ""
    parts = os.path.normpath(path).split(os.sep)
    lowered = [p.lower() for p in parts]
    # Pointing into the tables (...\windows, ...\windows\ntkrnlmp.pdb, or a table file): the folder
    # Volatility wants is the one above windows\ (or linux\, mac\). C:\Windows\... is not that.
    root = ""
    for i in range(len(parts) - 1, 0, -1):
        if lowered[i] in ("windows", "linux", "mac"):
            rest = lowered[i + 1:]
            if not rest or (len(rest) <= 2 and (rest[0].endswith(".pdb") or
                                                rest[-1].endswith((".json", ".json.xz", ".json.gz", ".json.bz2")))):
                root = os.sep.join(parts[:i])
            break
    if os.path.exists(path) and not os.path.isdir(path):
        return (f"memory.symbols_dir must be a folder, but it points to a file ({path}). "
                + (f"Use the folder that holds the windows folder: {root}" if root else
                   "Use a folder for symbol tables, e.g. C:\\dfir\\symbols") + ".")
    if root:
        return (f"memory.symbols_dir must be the folder that holds the windows folder, not a folder inside it. "
                f"Use: {root}")
    return ""


def yara_dir() -> str:
    path = settings.get("memory", "yara_dir", "DFIR_YARA_DIR", "")
    return os.path.abspath(str(path)) if path else ""


def rule_files() -> list:
    """YARA rule files the agent may use (names relative to yara_dir, one level deep)."""
    root = yara_dir()
    if not root or not os.path.isdir(root):
        return []
    found = []
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")] if folder == root else []
        found += [os.path.relpath(os.path.join(folder, f), root).replace("\\", "/") for f in files
                  if os.path.splitext(f)[1].lower() in (".yar", ".yara") and not f.startswith(".")]
    return sorted(found, key=str.lower)


def rule_path(name: str) -> str:
    """A rule file inside yara_dir (MemoryAnalysisError otherwise)."""
    root = yara_dir()
    if not root or not os.path.isdir(root):
        raise MemoryAnalysisError("No YARA rule folder is set up on this server (memory.yara_dir in server.yaml). "
                                  "Search for a text instead (text option).")
    path, real_root = os.path.realpath(os.path.join(root, str(name))), os.path.realpath(root)
    try:
        inside = os.path.commonpath([path, real_root]) == real_root
    except ValueError:
        inside = False
    if not inside or os.path.splitext(path)[1].lower() not in (".yar", ".yara") or not os.path.isfile(path):
        known = ", ".join(rule_files()) or "none"
        raise MemoryAnalysisError(f"No rule file '{name}' in the server's YARA folder. Available: {known}.")
    return path


def offline() -> bool:
    return settings.flag("memory", "offline", "DFIR_VOL_OFFLINE")


def timeout() -> int:
    return int(settings.get("memory", "timeout", "DFIR_VOL_TIMEOUT", 3600))


def command() -> list:
    """How to start Volatility: memory.command in server.yaml (a list), else this Python."""
    configured = settings.get("memory", "command", default=None)
    if isinstance(configured, list) and configured:
        return [str(c) for c in configured]
    if isinstance(configured, str) and configured.strip():
        return [configured.strip()]
    return [sys.executable, "-c", BOOT]


# ---------------------------------------------------------------- images
def available_images() -> list:
    """Memory images the investigator can pick: [{name, size}] relative to images_dir."""
    root = images_dir()
    if not root or not os.path.isdir(root):
        return []
    found = []
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")] if folder == root else []   # one level deep
        for name in files:
            if name.startswith(".") or os.path.splitext(name)[1].lower() not in IMAGE_EXTENSIONS:
                continue
            path = os.path.join(folder, name)
            found.append({"name": os.path.relpath(path, root).replace("\\", "/"), "size": os.path.getsize(path)})
    return sorted(found, key=lambda i: i["name"].lower())


def image_path(name: str = None) -> str:
    """The case's memory image as a path inside images_dir (MemoryAnalysisError if not usable)."""
    name = (case_config.memory_image if name is None else name) or ""
    if not name:
        raise MemoryAnalysisError("No memory image is set for this case. Pick one in the case settings "
                           "(the images in the server's memory folder are listed there).")
    root = images_dir()
    if not root:
        raise MemoryAnalysisError("Memory analysis is not set up on this server: set memory.images_dir in server.yaml "
                           "to the folder that holds the memory images.")
    path, real_root = os.path.realpath(os.path.join(root, name)), os.path.realpath(root)
    try:
        inside = os.path.commonpath([path, real_root]) == real_root
    except ValueError:          # Windows: different drives
        inside = False
    if not inside:
        raise MemoryAnalysisError(f"'{name}' is outside the server's memory folder.")
    if not os.path.isfile(path):
        raise MemoryAnalysisError(f"Memory image '{name}' was not found in the server's memory folder ({root}).")
    return path


def image_identity(path: str = None) -> dict:
    """
    Size, modification time and SHA-256 of the case's memory image, stored in the case database
    for the report (provenance). Hashed once per version of the file, so the first run on a large
    image takes a little longer; a file that changes later gets a second entry.
    """
    import hashlib
    path = path or image_path()
    source = f"memory:{case_config.memory_image}"
    stat = os.stat(path)
    modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
    known = case_db.evidence_file(source, stat.st_size, modified)
    if known:
        return known
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            digest.update(block)
    case_db.record_evidence_file(source, stat.st_size, modified, digest.hexdigest())
    case_db.log_query("evidence_hash", f"{case_config.memory_image}: SHA-256 {digest.hexdigest()} "
                                       f"({stat.st_size} bytes, modified {modified})", 0)
    return case_db.evidence_file(source, stat.st_size, modified)


def human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit in ("B", "KB") else f"{size:.1f} {unit}"
        size /= 1024


# ---------------------------------------------------------------- running Volatility
def resolve(plugin: str) -> tuple:
    """(short name, Plugin) for a short or full plugin name; MemoryAnalysisError if not allowed."""
    wanted = (plugin or "").strip()
    for short, spec in PLUGINS.items():
        if wanted.lower() == short or wanted in spec.names:
            return short, spec
    known = ", ".join(PLUGINS)
    raise MemoryAnalysisError(f"'{plugin}' is not an allowed memory plugin. Allowed: {known}.")


def check_options(short: str, spec: Plugin, options: dict, requested_by: str = "investigator") -> dict:
    """Validated options (only those the plugin allows)."""
    options = {k: v for k, v in (options or {}).items() if v not in (None, "", [], False)}
    unknown = set(options) - spec.options
    if unknown:
        allowed = ", ".join(sorted(spec.options)) or "none"
        raise MemoryAnalysisError(f"{short} does not take {', '.join(sorted(unknown))} (options: {allowed}).")
    if "pid" in options:
        pids = options["pid"] if isinstance(options["pid"], list) else [options["pid"]]
        try:
            options["pid"] = [int(p) for p in pids]
        except (TypeError, ValueError):
            raise MemoryAnalysisError("pid must be a list of process IDs (numbers).")
    if "recurse" in options and "key" not in options:
        raise MemoryAnalysisError("recurse needs a key.")
    if spec.needs_one_of and len(spec.needs_one_of & set(options)) != 1:
        raise MemoryAnalysisError(f"{short} searches memory: give exactly one of "
                                  f"{' or '.join(sorted(spec.needs_one_of))}.")
    if "text" in options:
        options["text"] = check_text(options["text"])
    if "words" in options:
        options["words"] = check_words(options["words"])
    if "rules" in options:
        rule_path(options["rules"])
    if requested_by == "agent" and spec.heavy and not ({"pid", "key", "contains"} & set(options)):
        raise MemoryAnalysisError(f"{short} returns a lot of rows for a whole memory image. Narrow it with "
                           f"{' or '.join(sorted(spec.options & {'pid', 'key', 'contains'}))}, based on a lead "
                           f"(e.g. a suspicious PID from pslist or a name you already found).")
    return options


MAX_WORDS = 20


def check_words(words) -> list:
    """Several texts searched in one pass (strings), e.g. the command names to list command lines."""
    words = [words] if isinstance(words, str) else list(words or [])
    words = list(dict.fromkeys(check_text(w) for w in words))
    if not 1 <= len(words) <= MAX_WORDS:
        raise MemoryAnalysisError(f"words must be 1 to {MAX_WORDS} texts.")
    return words


def check_text(text) -> str:
    """A text to search memory for: printable ASCII, long enough not to match everywhere."""
    text = str(text).strip()
    if not 4 <= len(text) <= 200 or any(not " " <= c <= "~" for c in text):
        raise MemoryAnalysisError("text must be 4 to 200 printable ASCII characters, e.g. an IP address, "
                                  "a domain, part of a URL or a file name.")
    return text


_YARA_META = set("\\^$.|?*+()[]{}/")


def yara_text_rule(text: str) -> str:
    """A YARA regex for the text plus the printable text that follows it (the rest of a URL)."""
    return "/" + "".join("\\" + c if c in _YARA_META else c for c in text) + "[ -~]{0,100}/"


def _arguments(options: dict, spec: Plugin = None) -> list:
    args = []
    if options.get("text") and spec is not None and spec.yara_string:
        args += ["--yara-string", yara_text_rule(options["text"]), "--wide", "--insensitive"]
    elif options.get("text"):
        args += ["--text", options["text"]]
    if options.get("rules"):
        args += ["--yara-file", rule_path(options["rules"])]
    if options.get("pid"):
        args += ["--pid", *[str(p) for p in options["pid"]]]
    if options.get("key"):
        args += ["--key", str(options["key"])]
    if options.get("recurse"):
        args.append("--recurse")
    return args


def _contains_filter(text: str) -> str:
    """Volatility's --filters: rows with the text in any column (case-insensitive regex, no commas)."""
    return "+(?i)" + re.escape(str(text)).replace(",", r"\x2c") + "!"


def available_plugins() -> set:
    """Plugin names the installed Volatility offers (cached per process)."""
    if _available["names"] is None:
        try:
            out = subprocess.run(command() + ["-p", PLUGIN_DIR, "--help"], capture_output=True, text=True,
                                 timeout=120,
                                 env=_env(), encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired) as e:
            raise MemoryAnalysisError(f"Volatility 3 could not be started ({e}). Install it on the server with "
                               f"'pip install volatility3' (same Python as the copilot).")
        text = out.stdout + out.stderr
        if "No module named" in text or out.returncode not in (0, 1):
            raise MemoryAnalysisError("Volatility 3 is not installed for this Python. Install it on the server with "
                               "'pip install volatility3'.")
        version = re.search(r"Volatility 3 Framework (\S+)", text)
        _available["version"] = version.group(1) if version else "unknown"
        _available["names"] = set(re.findall(r"^\s{4}([a-z][a-z0-9_]*(?:\.[A-Za-z0-9_]+)+)", text, re.M))
    return _available["names"]


_available = {"names": None, "version": None}


def version() -> str:
    available_plugins()
    return _available["version"]


def _env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def build_command(image: str, plugin_name: str, options: dict, spec: Plugin = None) -> list:
    cmd = command() + ["-p", PLUGIN_DIR, "-q", "-r", "json"]
    if symbols_problem():
        raise MemoryAnalysisError(symbols_problem())
    if symbols_dir():
        os.makedirs(symbols_dir(), exist_ok=True)
        cmd += ["-s", symbols_dir()]       # searched first; downloaded tables are saved here too
    if offline():
        cmd.append("--offline")
    if options.get("contains"):
        cmd += ["--filters", _contains_filter(options["contains"])]
    return cmd + ["-f", image, plugin_name] + _arguments(options, spec)


_LOG_LINE = re.compile(r"^(WARNING|INFO|DEBUG)\s+\S+:")


def _frame(line: str) -> str:
    """'File ".../volatility3/cli/text_renderer.py", line 545, in <lambda>' -> 'text_renderer.py:545 <lambda>'."""
    m = re.match(r'File "(.*?)", line (\d+), in (.*)', line)
    if not m:
        return line[:120]
    name = m.group(1).replace("\\", "/").rsplit("/", 1)[-1]
    return f"{name}:{m.group(2)} {m.group(3)}"


def explain_failure(output: str) -> str:
    """Volatility's own messages, plus what to do about the common ones."""
    lines = [line.strip() for line in output.splitlines()
             if line.strip() and not line.startswith("Volatility 3 Framework")]
    warnings = [line for line in lines if _LOG_LINE.match(line)]
    lines = [line for line in lines if not _LOG_LINE.match(line)]
    if "Traceback (most recent call last)" in output:
        # Volatility crashed: the exception (last line) and where it happened (last frames) say why;
        # the start of a long traceback does not.
        frames = [line for line in lines if line.startswith('File "')]
        where = " <- ".join(_frame(f) for f in reversed(frames[-3:]))
        raw = output.splitlines()
        last = max((i for i, line in enumerate(raw) if line.lstrip().startswith('File "')), default=-1)
        error = next((line.strip() for line in raw[last + 1:] if line.strip() and not line[0].isspace()),
                     lines[-1])          # the exception: the first unindented line after the last frame
        crash = f"Volatility stopped with an error: {error[:600]} (in {where})."
        if warnings:
            crash += f" Before that it warned {len(warnings)} time(s), e.g.: {warnings[0][:200]}"
        return crash
    text = " ".join(lines)[:1500]
    if "symbol_table_name" in output:
        where = symbols_dir() or "Volatility's symbols folder"
        if offline():
            hint = (f"Volatility has no symbol table for this image's kernel, and it is not allowed to download "
                    f"one (memory.offline). Put the Windows symbol pack (windows.zip) or the table for this "
                    f"kernel into {where}, or set memory.offline: false once on a server with internet: "
                    f"Volatility then downloads the table into {where} and the image works offline afterwards.")
        else:
            hint = (f"Volatility found no symbol table for this image's kernel and could not download one "
                    f"(no internet?). Put the Windows symbol pack (windows.zip) or the table into {where}.")
        if "layer_name" in output:
            hint += " If the file is not a complete memory image, Volatility can't read it either."
        return f"{hint} Volatility said: {text}"
    if "layer_name" in output:
        return f"Volatility could not read this file as a memory image. Volatility said: {text}"
    return text or "Volatility failed without a message."


def _rows(tree: list, depth: int = 0):
    """Flattens Volatility's tree output (pstree etc.): children follow their parent."""
    for node in tree or []:
        children = node.pop("__children", []) if isinstance(node, dict) else []
        if isinstance(node, dict) and depth:
            node["TreeDepth"] = depth
        yield node
        yield from _rows(children, depth + 1)


def run(plugin: str, options: dict = None, requested_by: str = "investigator") -> dict:
    """
    Runs one plugin on the case's memory image and stores its rows. Returns a summary like a
    collection's. requested_by="agent" applies the agent rules (heavy plugins need a filter,
    and the investigator approves first, as configured).
    """
    short, spec = resolve(plugin)
    options = check_options(short, spec, options, requested_by)
    image = image_path()
    if requested_by == "agent" and spec.names:
        blocked = unreadable_reason(case_config.memory_image)
        if blocked:
            raise MemoryAnalysisError(
                f"Volatility cannot read this memory image: {blocked[:300]} Do not retry Volatility plugins: "
                f"the investigator has to add the symbol table (python -m copilot.memory check). The 'strings' "
                f"plugin still works (it searches the image file itself).")
    if requested_by == "agent":
        from copilot import approvals
        shown = ", ".join(f"{k}={v}" for k, v in options.items())
        try:
            approvals.gate("memory", f"{short}{f' ({shown})' if shown else ''} on {case_config.memory_image}",
                           {"plugin": short, "options": options})
        except approvals.ApprovalError as e:
            raise MemoryAnalysisError(str(e))
    return execute(short, options, image)


def unreadable_reason(image_name: str) -> str:
    """The symbol-table error of the latest Volatility run on this image ("" if it worked since)."""
    client = f"memory:{image_name}"
    runs = sorted((c for c in case_db.get_collections() if c.get("client_id") == client
                   and str(c.get("flow_id", "")).startswith("MEM.")
                   and not str(c.get("flow_id", "")).startswith("MEM.strings.")),
                  key=lambda c: c.get("requested_at") or "")
    if runs and runs[-1].get("state") == "ERROR" and "symbol table" in (runs[-1].get("error") or ""):
        return runs[-1]["error"]
    return ""


def _plugin_name(short: str, spec: Plugin) -> str:
    """The plugin's name in the installed Volatility (names moved between versions)."""
    available = available_plugins()
    names = [n for n in spec.names if n in available]
    if not names:
        raise MemoryAnalysisError(f"{short} is not available in the installed Volatility ({version()})."
                                  + (f" {spec.requires}" if spec.requires else ""))
    return names[0]


def execute(short: str, options: dict, image: str = None) -> dict:
    """Runs an already approved plugin run."""
    _, spec = resolve(short)
    image = image or image_path()
    if spec.names:
        plugin_name = _plugin_name(short, spec)
        if options.get("rules") and YARA_PLUGIN not in available_plugins():
            raise MemoryAnalysisError(f"Scanning with YARA rules needs YARA. {YARA_INSTALL}")
        cmd = build_command(image, plugin_name, options, spec)   # settings problems surface before anything runs
    else:
        plugin_name, cmd = short, None                        # done here, not by Volatility
    try:
        image_identity(image)
    except OSError:
        pass                    # an unreadable file fails below, with Volatility's explanation
    started = datetime.now(timezone.utc)
    flow_id = f"MEM.{short}.{started.strftime('%Y%m%d%H%M%S%f')}"
    source = f"Memory.{plugin_name}"
    client = f"memory:{case_config.memory_image}"
    case_db.upsert_collection(flow_id, client_id=client, artifact=source,
                              parameters=json.dumps(options, sort_keys=True), state="RUNNING",
                              requested_at=started.isoformat())
    summary = {"artifact": source, "flow_id": flow_id, "image": case_config.memory_image}
    clock = time.monotonic()
    try:
        if cmd:
            code, stdout, stderr = _run_process(cmd)
        else:
            found, truncated = search_image(image, options.get("words") or options["text"])
            code, stdout, stderr = 0, json.dumps(found), ""
    except subprocess.TimeoutExpired:
        code, stdout, stderr = None, "", f"Stopped after {timeout()} s (memory.timeout)."
    except OSError as e:
        code, stdout, stderr = None, "", f"Could not read the image: {e}"
    seconds = round(time.monotonic() - clock)
    finished = datetime.now(timezone.utc).isoformat()
    if code != 0:
        error = explain_failure(stdout + "\n" + stderr) if code is not None else stderr
        case_db.upsert_collection(flow_id, state="ERROR", error=error[:4000], finished_at=finished)
        case_db.log_query("analyze_memory", f"{plugin_name} {json.dumps(options)} -> error", 0, source)
        return {**summary, "state": "ERROR", "error": error, "seconds": seconds}
    try:
        tree = json.loads(stdout.strip() or "[]")
    except ValueError:
        error = f"Volatility's output was not JSON: {explain_failure(stdout + chr(10) + stderr)}"
        case_db.upsert_collection(flow_id, state="ERROR", error=error[:4000], finished_at=finished)
        return {**summary, "state": "ERROR", "error": error, "seconds": seconds}
    returned = list(_rows(tree if isinstance(tree, list) else [tree]))
    if spec.post:
        returned = spec.post(returned, options)
    # Some scans report the same record many times (svcscan finds each service list from
    # several headers): keep one copy of identical rows.
    rows = list({json.dumps(r, sort_keys=True, default=str): r for r in returned}.values())
    limit = case_config.max_rows
    kept = rows[:limit]
    new = case_db.ingest_artifact_results(kept, source, hostname=os.path.basename(case_config.memory_image),
                                          client_id=client)
    case_db.upsert_collection(flow_id, state="FINISHED", finished_at=finished, rows_ingested=new, ingested=1)
    case_db.log_query("analyze_memory", f"{plugin_name} {json.dumps(options)}", len(kept), source)
    summary.update(state="FINISHED", rows_read=len(kept), new_rows_ingested=new, seconds=seconds)
    if len(returned) != len(rows):
        summary["duplicates_dropped"] = len(returned) - len(rows)
    if len(rows) > limit:
        summary["note"] = (f"Volatility returned {len(rows)} distinct rows; only the first {limit} were stored "
                           f"(collection.max_rows). Narrow it with pid or contains.")
    elif not rows:
        summary["note"] = "No rows (nothing matched, or nothing of this kind in this image)."
        if short == "strings":
            summary["note"] = ("The text is nowhere in the image file (ASCII or UTF-16). If the image is "
                               "compressed (e.g. some crash dumps or snapshots), this search can't see inside it.")
        elif spec.searches:
            summary["note"] = ("No process's memory holds it now. Freed memory and exited processes are not "
                               "covered: the strings plugin searches the whole image file.")
    if not cmd and truncated:
        summary["note"] = f"Stopped after {MAX_STRING_HITS} hits: use a longer, more specific text."
    return summary


def _context(data: bytes, start: int, end: int, step: int) -> tuple:
    """Printable text before start (up to _BEFORE characters) and from start on (match + up to _AFTER)."""
    def printable(i):
        return 0x20 <= data[i] <= 0x7E and (step == 1 or data[i + 1] == 0)

    i = start
    while i - step >= 0 and (start - i) // step < _BEFORE and printable(i - step):
        i -= step
    j = end
    while j + step <= len(data) and (j - end) // step < _AFTER and printable(j):
        j += step
    return data[i:start][::step].decode("latin-1"), data[start:j][::step].decode("latin-1")


def search_image(path: str, text, max_hits: int = MAX_STRING_HITS) -> tuple:
    """
    The `strings` plugin: every place the image file holds `text` (a text or a list of texts;
    case-insensitive, ASCII and UTF-16LE), with the printable text around it. Returns (one row per
    distinct context, whether it stopped at max_hits).
    """
    needles = []
    for word in ([text] if isinstance(text, str) else text):
        needle = word.lower().encode("ascii")
        needles += [(needle, 1, "ASCII"), (b"".join(bytes([c]) + b"\0" for c in needle), 2, "UTF-16")]
    margin = (_BEFORE + _AFTER) * 2 + max(len(n[0]) for n in needles)
    grouped, hits, offset = {}, 0, 0
    with open(path, "rb") as f:
        while hits < max_hits:
            f.seek(max(0, offset - margin))
            head = offset - max(0, offset - margin)
            data = f.read(head + _CHUNK + margin)
            if len(data) <= head:
                break
            lowered = data.lower()
            for pattern, step, encoding in needles:
                at = lowered.find(pattern, head)
                while at != -1 and at < head + _CHUNK and hits < max_hits:
                    before, match = _context(data, at, at + len(pattern), step)
                    key = (encoding, before, match)
                    if key in grouped:
                        grouped[key]["Hits"] += 1
                    else:
                        grouped[key] = {"Offset": hex(offset - head + at), "Encoding": encoding,
                                        "Before": before, "Match": match, "Hits": 1}
                    hits += 1
                    at = lowered.find(pattern, at + 1)
            offset += _CHUNK
    return sorted(grouped.values(), key=lambda r: int(r["Offset"], 16)), hits >= max_hits


def _run_process(cmd: list) -> tuple:
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout(), env=_env(),
                         encoding="utf-8", errors="replace")
    return out.returncode, out.stdout, out.stderr


def triage_plan(config=None) -> list:
    """A case's memory triage (the active case's by default): memory.collect, else the defaults for memory.os."""
    config = config or case_config
    return config.memory_plan or TRIAGE.get(config.memory_os, TRIAGE["windows"])


def triage(progress=None, plugins: list = None) -> list:
    """
    Runs the memory triage plugins (investigator action, no approval): `plugins`, else the case's
    list. Failures are reported, not raised.
    """
    try:                 # problems every plugin would hit: report once
        image_path()
        available_plugins()
        if symbols_problem():
            raise MemoryAnalysisError(symbols_problem())
    except MemoryAnalysisError as e:
        return [{"artifact": "Memory triage", "state": "NOT_STARTED", "error": str(e)}]
    summaries = []
    for plugin in plugins or triage_plan():
        if progress:
            progress(plugin)
        try:
            summary = run(plugin, {})
        except MemoryAnalysisError as e:
            summary = {"artifact": f"Memory.{plugin}", "state": "NOT_STARTED", "error": str(e)}
        summaries.append(summary)
    return summaries


def triage_plugins(os_name: str = None) -> list:
    """Plugins that can be part of a memory triage (not the searches, which need a text or rules)."""
    prefix = (os_name or case_config.memory_os) + "."
    return [short for short, spec in PLUGINS.items() if short.startswith(prefix) and not spec.searches]


def plugin_list() -> list:
    listed = []
    for short, spec in PLUGINS.items():
        item = {"plugin": short, "about": spec.about, "options": sorted(spec.options),
                "needs_filter_for_agent": spec.heavy}
        if spec.searches:
            item["needs_one_of"] = sorted(spec.needs_one_of)
        if "rules" in spec.options:
            item["rule_files"] = rule_files()
        listed.append(item)
    return listed


# ---------------------------------------------------------------- server check (CLI)
def check(image: str = None) -> int:
    """python -m copilot.memory check [image]: is Volatility usable here, offline included?"""
    ok = True
    print(f"Volatility command: {' '.join(command()[:2])} ...")
    try:
        print(f"Volatility 3 version: {version()} ({len(available_plugins())} plugins)")
    except MemoryAnalysisError as e:
        print(f"[!] {e}")
        return 1
    root = images_dir()
    if not root:
        print("[!] memory.images_dir is not set in server.yaml: no memory image can be used.")
        ok = False
    elif not os.path.isdir(root):
        print(f"[!] memory.images_dir {root} does not exist.")
        ok = False
    else:
        images = available_images()
        print(f"Memory images in {root}: {len(images)}")
        for item in images:
            print(f"  - {item['name']} ({human_size(item['size'])})")
    syms = symbols_dir()
    if symbols_problem():
        print(f"[!] {symbols_problem()}")
        return 1
    if syms:
        packs = [n for n in ("windows.zip", "linux.zip", "mac.zip") if os.path.isfile(os.path.join(syms, n))]
        tables = sum(1 for _, _, files in os.walk(syms) for f in files if f.endswith((".json.xz", ".json")))
        print(f"Symbols folder {syms}: packs {', '.join(packs) or 'none'}, {tables} table files")
    else:
        print("Symbols: Volatility's own folders (memory.symbols_dir not set)")
    print(f"Offline: {'yes, nothing is downloaded' if offline() else 'no, missing symbols are downloaded'}")
    if YARA_PLUGIN in available_plugins():
        print("YARA: available (rule files can be used)")
    else:
        print(f"[i] YARA rule scans are off (text searches work without): {YARA_INSTALL}")
    if yara_dir():
        state = f"{len(rule_files())} rule files" if os.path.isdir(yara_dir()) else "does not exist"
        print(f"YARA rule folder {yara_dir()}: {state}")
    if image:
        try:
            path = image_path(image)
        except MemoryAnalysisError as e:
            print(f"[!] {e}")
            return 1
        print(f"\nRunning windows.info on {image} (can take a few minutes the first time)...")
        code, stdout, stderr = _run_process(build_command(path, "windows.info.Info", {}))
        if code == 0:
            rows = {r.get("Variable"): r.get("Value") for r in json.loads(stdout.strip() or "[]")}
            print(f"OK: Windows {rows.get('NtMajorVersion')}.{rows.get('NtMinorVersion')} build "
                  f"{str(rows.get('Major/Minor', '')).split('.')[-1]}, captured {rows.get('SystemTime')}")
            print(f"Symbol table: {rows.get('Symbols')}")
        else:
            print(f"[!] {explain_failure(stdout + chr(10) + stderr)}")
            ok = False
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] != "check":
        print("Usage: python -m copilot.memory check [image name in memory.images_dir]")
        return 1
    return check(argv[1] if len(argv) > 1 else None)


if __name__ == "__main__":
    sys.exit(main())
