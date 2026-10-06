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
    "Windows.Sys.Users",
    "Windows.System.Amcache*",
    "Windows.System.Powershell.PSReadline",
    "Windows.System.TaskScheduler",
    "Windows.System.Services",
    "Generic.Forensic.*",
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

CLIENT_ID_RE = re.compile(r"^C\.[0-9a-fA-F]{8,32}$")


class CaseConfig:
    """Loads and provides access to the case.yaml scope file."""

    def __init__(self, path=None):
        self.path = path or os.environ.get("DFIR_CASE_FILE", "case.yaml")
        self.data = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = yaml.safe_load(f) or {}

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
    def artifacts_to_collect(self) -> list:
        explicit = self.data.get("collect", None)
        if explicit and isinstance(explicit, list) and len(explicit) > 0:
            return explicit
        return DEFAULT_TRIAGE_ARTIFACTS

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

    @property
    def artifact_allowlist(self) -> list:
        allow = (self.data.get("artifacts", {}) or {}).get("allow")
        return allow if isinstance(allow, list) and allow else DEFAULT_ARTIFACT_ALLOWLIST

    def is_artifact_allowed(self, name: str) -> bool:
        if any(fnmatch.fnmatchcase(name, pat) for pat in ARTIFACT_DENYLIST):
            return False
        return any(fnmatch.fnmatchcase(name, pat) for pat in self.artifact_allowlist)

    @property
    def allow_raw_vql(self) -> bool:
        return bool((self.data.get("agent", {}) or {}).get("allow_raw_vql", False))

    def build_system_context(self) -> str:
        """Build a context block to inject into the LLM system prompt."""
        lines = [f"Case: {self.case_name}", f"Analyst: {self.analyst}"]
        if self.client_id and not self.client_id_error:
            lines.append(f"Evidence client (dead-disk image): {self.client_id}")

        if self.has_scope:
            lines.append(f"\nINCIDENT SCOPE:")
            lines.append(f"  Time Window: {self.start_time} → {self.end_time}")
            if self.description:
                lines.append(f"  Description: {self.description}")

        if self.has_iocs:
            lines.append(f"\nKNOWN IOCs:")
            for category, values in self.iocs.items():
                if values:
                    lines.append(f"  {category}: {', '.join(str(v) for v in values)}")

        if not self.has_scope and not self.has_iocs:
            lines.append("\nNo incident scope or IOCs provided. Run a general triage.")

        return "\n".join(lines)


# Global instance
case_config = CaseConfig()
