import os
import yaml


# Default triage artifacts when no case.yaml scope is provided
DEFAULT_TRIAGE_ARTIFACTS = [
    "Generic.Client.Info",
    "Windows.Timeline.Prefetch",
    "Windows.System.Powershell.PSReadline",
    "Windows.System.TaskScheduler",
]


class CaseConfig:
    """Loads and provides access to the case.yaml scope file."""

    def __init__(self, path="case.yaml"):
        self.path = path
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

    def build_system_context(self) -> str:
        """Build a context block to inject into the LLM system prompt."""
        lines = [f"Case: {self.case_name}", f"Analyst: {self.analyst}"]

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
