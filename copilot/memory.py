"""
Memory analysis with Volatility 3, against the case's memory image.

Server (server.yaml, see copilot/settings.py):
    memory:
      images_dir: D:\\dfir\\memory     # memory images the copilot may open
      symbols_dir: D:\\dfir\\symbols   # Windows symbol tables: windows.zip and/or downloaded tables
      offline: true                    # never download symbols (Volatility's --offline)
      timeout: 3600                    # seconds per plugin run

Case (case.yaml):
    memory:
      image: DESKTOP-SDN1RPT.mem       # a file in images_dir (chosen in the app's case settings)
      os: windows                      # windows | linux: picks the default triage plugins
      collect: [windows.pslist, ...]   # optional: the memory triage list

Volatility runs as a separate process with the copilot's own Python (pip install volatility3),
rendering JSON. Its rows go into the case database like collected artifacts (source
"Memory.<plugin>"), so the timeline, search, findings and report include them.

Only the plugins in PLUGINS can run, with only the options listed there: nothing that dumps
files, writes outside the case, or reads anything but an image in images_dir.
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

# Runs Volatility's command line with this Python (the `vol` script is often not on PATH).
BOOT = "import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; main()"
IMAGE_EXTENSIONS = {".mem", ".raw", ".vmem", ".dmp", ".lime", ".bin", ".img", ".dd", ".mddramimage",
                    ".core", ".elf", ".vmsn", ".vmss", ".hpak", ".crash"}


class MemoryAnalysisError(Exception):
    """Memory analysis could not run; the message is safe to show to the agent or user."""


class Plugin:
    def __init__(self, names, about, options=(), heavy=False):
        self.names = names            # full Volatility names, newest first (renamed between versions)
        self.about = about
        self.options = set(options)   # pid | key | recurse | contains
        self.heavy = heavy            # the agent must narrow it (pid / key / contains)


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
}

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
    if requested_by == "agent" and spec.heavy and not ({"pid", "key", "contains"} & set(options)):
        raise MemoryAnalysisError(f"{short} returns a lot of rows for a whole memory image. Narrow it with "
                           f"{' or '.join(sorted(spec.options & {'pid', 'key', 'contains'}))}, based on a lead "
                           f"(e.g. a suspicious PID from pslist or a name you already found).")
    return options


def _arguments(options: dict) -> list:
    args = []
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
            out = subprocess.run(command() + ["--help"], capture_output=True, text=True, timeout=120,
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
        _available["names"] = set(re.findall(r"^\s{4}((?:windows|linux|mac)\.[\w.]+)", text, re.M))
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


def build_command(image: str, plugin_name: str, options: dict) -> list:
    cmd = command() + ["-q", "-r", "json"]
    if symbols_problem():
        raise MemoryAnalysisError(symbols_problem())
    if symbols_dir():
        os.makedirs(symbols_dir(), exist_ok=True)
        cmd += ["-s", symbols_dir()]       # searched first; downloaded tables are saved here too
    if offline():
        cmd.append("--offline")
    if options.get("contains"):
        cmd += ["--filters", _contains_filter(options["contains"])]
    return cmd + ["-f", image, plugin_name] + _arguments(options)


def explain_failure(output: str) -> str:
    """Volatility's own messages, plus what to do about the common ones."""
    lines = [line.strip() for line in output.splitlines()
             if line.strip() and not line.startswith("Volatility 3 Framework")]
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
    if requested_by == "agent":
        from copilot import approvals
        shown = ", ".join(f"{k}={v}" for k, v in options.items())
        try:
            approvals.gate("memory", f"{short}{f' ({shown})' if shown else ''} on {case_config.memory_image}",
                           {"plugin": short, "options": options})
        except approvals.ApprovalError as e:
            raise MemoryAnalysisError(str(e))
    return execute(short, options, image)


def _plugin_name(short: str, spec: Plugin) -> str:
    """The plugin's name in the installed Volatility (names moved between versions)."""
    available = available_plugins()
    names = [n for n in spec.names if n in available]
    if not names:
        raise MemoryAnalysisError(f"{short} is not available in the installed Volatility ({version()}).")
    return names[0]


def execute(short: str, options: dict, image: str = None) -> dict:
    """Runs an already approved plugin run."""
    _, spec = resolve(short)
    image = image or image_path()
    plugin_name = _plugin_name(short, spec)
    cmd = build_command(image, plugin_name, options)      # settings problems surface before anything runs
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
        code, stdout, stderr = _run_process(cmd)
    except subprocess.TimeoutExpired:
        code, stdout, stderr = None, "", f"Stopped after {timeout()} s (memory.timeout)."
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
    rows = list(_rows(tree if isinstance(tree, list) else [tree]))
    limit = case_config.max_rows
    kept = rows[:limit]
    new = case_db.ingest_artifact_results(kept, source, hostname=os.path.basename(case_config.memory_image),
                                          client_id=client)
    case_db.upsert_collection(flow_id, state="FINISHED", finished_at=finished, rows_ingested=new, ingested=1)
    case_db.log_query("analyze_memory", f"{plugin_name} {json.dumps(options)}", len(kept), source)
    summary.update(state="FINISHED", rows_read=len(kept), new_rows_ingested=new, seconds=seconds)
    if len(rows) > limit:
        summary["note"] = (f"Volatility returned {len(rows)} rows; only the first {limit} were stored "
                           f"(collection.max_rows). Narrow it with pid or contains.")
    elif not rows:
        summary["note"] = "No rows (nothing matched, or nothing of this kind in this image)."
    return summary


def _run_process(cmd: list) -> tuple:
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout(), env=_env(),
                         encoding="utf-8", errors="replace")
    return out.returncode, out.stdout, out.stderr


def triage_plan() -> list:
    """The case's memory triage: memory.collect, else the defaults for memory.os."""
    plan = case_config.memory_plan
    return plan or TRIAGE.get(case_config.memory_os, TRIAGE["windows"])


def triage(progress=None) -> list:
    """Runs the memory triage plugins (investigator action, no approval). Failures are reported, not raised."""
    try:                 # problems every plugin would hit: report once
        image_path()
        available_plugins()
        if symbols_problem():
            raise MemoryAnalysisError(symbols_problem())
    except MemoryAnalysisError as e:
        return [{"artifact": "Memory triage", "state": "NOT_STARTED", "error": str(e)}]
    summaries = []
    for plugin in triage_plan():
        if progress:
            progress(plugin)
        try:
            summary = run(plugin, {})
        except MemoryAnalysisError as e:
            summary = {"artifact": f"Memory.{plugin}", "state": "NOT_STARTED", "error": str(e)}
        summaries.append(summary)
    return summaries


def plugin_list() -> list:
    return [{"plugin": short, "about": spec.about, "options": sorted(spec.options),
             "needs_filter_for_agent": spec.heavy} for short, spec in PLUGINS.items()]


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
