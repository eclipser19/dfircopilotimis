import fnmatch
import os
import re
import yaml


# Default triage artifacts when no case.yaml scope is provided
DEFAULT_TRIAGE_ARTIFACTS = [
    "Generic.Client.Info",
    "Windows.Timeline.Prefetch",
    "Windows.System.Powershell.PSReadline",
    "Windows.System.TaskScheduler",
]


# Artifacts the agent may collect when case.yaml doesn't set `artifacts.allow`.
# Read-only parsers that make sense against a dead disk.
DEFAULT_ARTIFACT_ALLOWLIST = [
    "Generic.Client.Info",
    "Windows.EventLogs.*",
    "Windows.Forensics.*",
    "Windows.Timeline.*",
    "Windows.NTFS.*",
    "Windows.Registry.*",
    "Windows.Persistence.*",
    "Windows.Applications.*",
    "Windows.Analysis.EvidenceOfDownload",
    "Windows.Search.FileFinder",
    "Windows.Sys.Users",
    "Windows.Sys.StartupItems",
    "Windows.System.Amcache*",
    "Windows.System.Powershell.PSReadline",
    "Windows.System.TaskScheduler",
    "Windows.System.Services",
    "Generic.Forensic.*",
    "Generic.Detection.Logs",
    "Linux.Forensics.*",
    "Linux.Syslog.*",
    "Linux.Ssh.*",
    "Linux.Sys.Users",
    "Linux.Sys.LastUserLogin",
    "Linux.Sys.Crontab",
]

# Never collectable, whatever the allowlist says: these run commands,
# change the endpoint, or act on the server.
ARTIFACT_DENYLIST = [
    "Windows.System.PowerShell",
    "Windows.System.CmdShell",
    "Linux.Sys.BashShell",
    "*.Remediation.*",
    "Server.*",
    "Admin.*",
]

# Artifacts that can return millions of rows. When the agent asks for one, it must
# pass at least one filter parameter beyond the time window.
HEAVY_ARTIFACTS = [
    "Windows.NTFS.MFT*",
    "Windows.Timeline.MFT*",
    "Windows.NTFS.Usn*",
    "Windows.Forensics.Usn*",
    "Windows.EventLogs.EvtxHunter*",
    "Windows.Search.*",
    "Windows.KapeFiles.*",
    "Generic.Forensic.Timeline*",
]

AGENT_COLLECTION_MODES = ("confirm", "auto", "off")

CLIENT_ID_RE = re.compile(r"^C\.[0-9a-fA-F]{8,32}$")


def cases_dir() -> str:
    """Folder holding one sub-folder per case: <cases_dir>/<case-id>/case.yaml."""
    return os.environ.get("DFIR_CASES_DIR", "cases")


def initial_case_file() -> str:
    """DFIR_CASE_FILE, else the case named by DFIR_CASE, else the legacy root case.yaml."""
    if os.environ.get("DFIR_CASE_FILE"):
        return os.environ["DFIR_CASE_FILE"]
    if os.environ.get("DFIR_CASE"):
        return os.path.join(cases_dir(), os.environ["DFIR_CASE"], "case.yaml")
    return "case.yaml"


class CaseConfig:
    """Loads and provides access to the case.yaml scope file."""

    def __init__(self, path=None):
        self.path = path or initial_case_file()
        self.data = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = yaml.safe_load(f) or {}

    def switch(self, path: str):
        """Loads another case file in place (every module holding case_config sees it)."""
        self.path = path
        self.data = {}
        self._load()

    @property
    def case_name(self) -> str:
        return self.data.get("case", {}).get("name", "Unnamed Case")

    @property
    def analyst(self) -> str:
        return self.data.get("case", {}).get("analyst", "Unknown")

    @property
    def start_time(self) -> str:
        return self.data.get("scope", {}).get("start_time", "") or ""

    @property
    def end_time(self) -> str:
        return self.data.get("scope", {}).get("end_time", "") or ""

    @property
    def description(self) -> str:
        return self.data.get("scope", {}).get("description", "") or ""

    @property
    def clock_offset_minutes(self) -> int:
        """How far the evidence host's clock ran AHEAD of true UTC (negative = behind)."""
        return int(self.data.get("scope", {}).get("clock_offset_minutes", 0) or 0)

    @property
    def has_scope(self) -> bool:
        return bool(self.start_time and self.end_time)

    @property
    def iocs(self) -> dict:
        defaults = {"hashes": [], "ips": [], "domains": [], "filenames": [], "users": []}
        return {**defaults, **(self.data.get("iocs", {}) or {})}

    @property
    def all_ioc_values(self) -> list:
        """Flat list of every IOC value for searching."""
        values = []
        for v in self.iocs.values():
            if isinstance(v, list):
                values.extend(v)
        return values

    @property
    def has_iocs(self) -> bool:
        return bool(self.all_ioc_values)

    @property
    def collection_plan(self) -> list:
        """
        Triage collections as [{"artifact": name, "parameters": {...}}]. `collect:` entries
        are either a bare artifact name or {artifact: ..., parameters: {...}}.
        """
        explicit = self.data.get("collect", None)
        entries = explicit if isinstance(explicit, list) and explicit else DEFAULT_TRIAGE_ARTIFACTS
        plan = []
        for entry in entries:
            if isinstance(entry, str):
                plan.append({"artifact": entry, "parameters": {}})
            elif isinstance(entry, dict) and entry.get("artifact"):
                plan.append({"artifact": str(entry["artifact"]), "parameters": dict(entry.get("parameters") or {})})
        return plan

    @property
    def artifacts_to_collect(self) -> list:
        return [step["artifact"] for step in self.collection_plan]

    # --- Velociraptor target & guardrails ---
    @property
    def client_id(self) -> str:
        """The single Velociraptor client (the dead-disk virtual client) this case may touch."""
        return str(self.data.get("velociraptor", {}).get("client_id", "") or "").strip()

    @property
    def client_id_error(self) -> str:
        """Empty when client_id is usable, otherwise a message for the investigator."""
        if not self.client_id:
            return (f"No velociraptor.client_id set in {self.path}. Find the dead-disk "
                    f"virtual client with `search_clients` and add its ID to the case file.")
        if not CLIENT_ID_RE.match(self.client_id):
            return f"velociraptor.client_id '{self.client_id}' is not a valid client ID (expected C.<hex>)."
        return ""

    @property
    def collection_wait_seconds(self) -> int:
        return int(self.data.get("velociraptor", {}).get("collection_wait_seconds", 120))

    # --- Collection limits ---
    def _collection(self) -> dict:
        return self.data.get("collection", {}) or {}

    @property
    def max_rows(self) -> int:
        """Most rows any single collection may return / ingest."""
        return int(self._collection().get("max_rows", 50000))

    @property
    def apply_time_window(self) -> bool:
        """Pass the case scope into artifacts' own date filters (DateAfter/DateBefore...)."""
        return bool(self._collection().get("apply_time_window", True))

    @property
    def agent_collections(self) -> str:
        """confirm: investigator approves each agent collection; auto: no prompt; off: agent can't collect."""
        mode = str(self._collection().get("agent_collections", "confirm")).lower()
        return mode if mode in AGENT_COLLECTION_MODES else "confirm"

    @staticmethod
    def is_heavy(name: str) -> bool:
        return any(fnmatch.fnmatchcase(name, pat) for pat in HEAVY_ARTIFACTS)

    @property
    def artifact_allowlist(self) -> list:
        allow = (self.data.get("artifacts", {}) or {}).get("allow")
        return allow if isinstance(allow, list) and allow else DEFAULT_ARTIFACT_ALLOWLIST

    def is_artifact_allowed(self, name: str) -> bool:
        if any(fnmatch.fnmatchcase(name, pat) for pat in ARTIFACT_DENYLIST):
            return False
        return any(fnmatch.fnmatchcase(name, pat) for pat in self.artifact_allowlist)

    @property
    def max_steps(self) -> int:
        """LLM calls allowed per investigator turn."""
        return int((self.data.get("agent", {}) or {}).get("max_steps", 20))

    @property
    def max_tokens_per_turn(self) -> int:
        """Token budget (input + output, all LLM calls) per investigator turn."""
        return int((self.data.get("agent", {}) or {}).get("max_tokens_per_turn", 300000))

    @property
    def report_formats(self) -> list:
        """Report files to write: any of html, md. Default: html only."""
        raw = (self.data.get("output", {}) or {}).get("report_formats", ["html"])
        formats = [str(f).lower().lstrip(".") for f in (raw if isinstance(raw, list) else [raw])]
        formats = [f for f in formats if f in ("html", "md")]
        return formats or ["html"]

    # --- Memory image (Volatility; see copilot/memory.py) ---
    def _memory(self) -> dict:
        memory = self.data.get("memory", {}) or {}
        return memory if isinstance(memory, dict) else {}

    @property
    def memory_image(self) -> str:
        """File name of the case's memory image inside the server's memory folder ("" = none)."""
        return str(self._memory().get("image", "") or "").strip()

    @property
    def memory_os(self) -> str:
        os_name = str(self._memory().get("os", "windows") or "windows").lower()
        return os_name if os_name in ("windows", "linux") else "windows"

    @property
    def memory_plan(self) -> list:
        """Memory triage plugins from the case file ([] = the defaults for memory.os)."""
        plan = self._memory().get("collect")
        return [str(p) for p in plan] if isinstance(plan, list) else []

    @property
    def allow_raw_vql(self) -> bool:
        return bool((self.data.get("agent", {}) or {}).get("allow_raw_vql", False))

    def build_system_context(self) -> str:
        """Build a context block to inject into the LLM system prompt."""
        lines = [f"Case: {self.case_name}", f"Analyst: {self.analyst}"]
        if self.client_id and not self.client_id_error:
            lines.append(f"Evidence client (dead-disk image): {self.client_id}")
        if self.memory_image:
            lines.append(f"Memory image: {self.memory_image} ({self.memory_os}; analyze with analyze_memory)")

        if self.has_scope:
            lines.append(f"\nINCIDENT SCOPE:")
            lines.append(f"  Time Window: {self.start_time} → {self.end_time}")
            if self.description:
                lines.append(f"  Description: {self.description}")

        if self.clock_offset_minutes:
            ahead = self.clock_offset_minutes > 0
            n = abs(self.clock_offset_minutes)
            lines.append(
                f"\nHOST CLOCK SKEW: the evidence host's clock ran {n} minutes {'AHEAD of' if ahead else 'BEHIND'} "
                f"true UTC. ALL host-recorded times are affected, including event logs and NTFS (they are "
                f"computed from the skewed clock). The database shows recorded times. When reporting, give "
                f"the corrected time ({'subtract' if ahead else 'add'} {n} minutes) and the recorded time, "
                f"e.g. '02:35:54 UTC (recorded 03:35:54)'. Query the database with recorded times. Tool "
                f"results already give the corrected time next to each recorded one (true_utc beside "
                f"timestamp_utc, first_seen_true_utc / last_seen_true_utc): copy those, never calculate.")

        if self.has_iocs:
            lines.append(f"\nKNOWN IOCs:")
            for category, values in self.iocs.items():
                if values:
                    lines.append(f"  {category}: {', '.join(str(v) for v in values)}")

        if not self.has_scope and not self.has_iocs:
            lines.append("\nNo incident scope or IOCs provided. Run a general triage.")

        return "\n".join(lines)


# The active case of the current session (see copilot/session.py).
from copilot.session import CaseView  # noqa: E402
case_config = CaseView("config")
