"""
Files recognised by their content, not their name (knowledge_data/file_types.yaml).

Each type becomes a YARA rule FileType_<type> on the file's first bytes. A collection parameter whose
value is "@file_types" (the triage's Generic.Detection.Yara.Glob, or an agent request) is sent to
Velociraptor as those rules; the collection keeps "@file_types" in its stored parameters and audit
line. `mismatch()` says whether a typed file's extension is one that type normally has: a 7-Zip
archive without an extension, a program named like a picture (leads.py lists them).
"""
import fnmatch
import functools
import ntpath

from copilot import knowledge

PARAMETER = "@file_types"
RULE_PREFIX = "FileType_"
# Download and copy suffixes that hide the real extension in front of them (setup.exe.crdownload).
TEMPORARY_SUFFIXES = {"crdownload", "partial", "part", "download", "opdownload", "tmp"}


@functools.lru_cache(maxsize=1)
def types() -> tuple:
    return tuple(knowledge._load("file_types.yaml"))


def by_rule() -> dict:
    return {RULE_PREFIX + t["type"]: t for t in types()}


def yara_rules() -> str:
    rules = []
    for t in types():
        what = t["what"].replace("\\", "\\\\").replace('"', '\\"')
        strings = f"\n  strings:\n    {t['strings']}" if t.get("strings") else ""
        rules.append(f'rule {RULE_PREFIX}{t["type"]} {{\n  meta:\n    what = "{what}"{strings}\n'
                     f'  condition:\n    {t["condition"]}\n}}')
    return "\n".join(rules) + "\n"


def resolve(params: dict) -> dict:
    """The parameters as Velociraptor gets them: "@file_types" becomes the YARA rules."""
    return {k: (yara_rules() if isinstance(v, str) and v.strip() == PARAMETER else v) for k, v in (params or {}).items()}


def extension(path: str) -> str:
    """Lower-case extension of a Windows or POSIX path ("" if none), looking past download suffixes."""
    name = ntpath.basename(str(path or "").replace("/", "\\")).lower()
    parts = name.lstrip(".").split(".")
    while len(parts) > 2 and parts[-1] in TEMPORARY_SUFFIXES:
        parts.pop()
    return parts[-1] if len(parts) > 1 else ""


def mismatch(path: str, rule: str) -> dict:
    """{"content", "extension"} when a file of this type does not normally have this extension, else {}."""
    kind = by_rule().get(rule)
    if not kind:
        return {}
    ext = extension(path)
    if any(fnmatch.fnmatchcase(ext, pattern) for pattern in kind.get("extensions") or []):
        return {}
    return {"content": kind["what"], "extension": ext or "(none)"}
