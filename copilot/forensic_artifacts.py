"""
Where Windows and applications keep their data, from the ForensicArtifacts project
(github.com/ForensicArtifacts/artifacts, Apache-2.0): file paths and registry keys for a few hundred
kinds of evidence. Our own knowledge base (knowledge_data/artifacts.yaml) describes Velociraptor
artifacts; this one answers "where is X stored?" when no artifact covers X, so the agent can read it
with Windows.Search.FileFinder (files, or machine registry with Accessor "registry") or
Windows.Registry.NTUser (per-user registry).

A pinned snapshot is converted once into knowledge_data/forensic_artifacts.yaml:
    python -m copilot.forensic_artifacts import <checkout of ForensicArtifacts/artifacts>
Path placeholders (%%users.homedir%%, %%environ_systemroot%%, ...) become globs for an image
mounted as C:, CurrentControlSet becomes ControlSet001 (an image has no CurrentControlSet), and
WMI / command sources (live systems only) are dropped.
"""
import functools
import os
import re
import shutil
import subprocess
import sys

import yaml

DATA_FILE = os.path.join(os.path.dirname(__file__), "knowledge_data", "forensic_artifacts.yaml")
LICENSE_FILE = os.path.join(os.path.dirname(__file__), "knowledge_data", "forensic_artifacts.LICENSE")

_VARS = {
    "%%users.homedir%%": r"C:\Users\*",
    "%%users.userprofile%%": r"C:\Users\*",
    "%%users.localappdata%%": r"C:\Users\*\AppData\Local",
    "%%users.appdata%%": r"C:\Users\*\AppData\Roaming",
    "%%users.temp%%": r"C:\Users\*\AppData\Local\Temp",
    "%%users.username%%": "*",
    "%%users.sid%%": "*",
    "%%environ_systemroot%%": r"C:\Windows",
    "%%environ_windir%%": r"C:\Windows",
    "%%environ_systemdrive%%": "C:",
    "%%environ_programfiles%%": r"C:\Program Files",
    "%%environ_programfilesx86%%": r"C:\Program Files (x86)",
    "%%environ_programdata%%": r"C:\ProgramData",
    "%%environ_allusersappdata%%": r"C:\ProgramData",
    "%%environ_allusersprofile%%": r"C:\ProgramData",
}
# Placeholders that only occur in Windows paths (a path starting with %%users.homedir%%/ may be macOS).
_WINDOWS_ONLY = ("%%environ_", "%%users.localappdata%%", "%%users.appdata%%", "%%users.temp%%",
                 "%%users.userprofile%%")
_USER_HIVE = re.compile(r"(?i)^(?:HKEY_USERS\\%%users\.sid%%|HKEY_CURRENT_USER)\\")


def _windows(source: dict, definition: dict) -> bool:
    return "Windows" in (source.get("supported_os") or definition.get("supported_os") or [])


def _expand(text: str):
    """Placeholders replaced, or None if one is unknown."""
    for var, value in _VARS.items():
        text = text.replace(var, value)
    return None if "%%" in text else text


def convert_path(path: str):
    """A ForensicArtifacts file path as a glob on the image, or None if it is not a Windows path."""
    if "\\" not in path and not path.startswith(_WINDOWS_ONLY):
        return None                                  # /Library/..., ~/.config/...: other systems
    path = re.sub(r"\*\*\d+", "**", path).replace("/", "\\")
    if path.startswith("\\"):                            # \Boot\BCD: from the root of the drive
        path = "C:" + path
    return _expand(path)


def convert_key(key: str, value: str = None) -> tuple:
    """
    (kind, glob): kind 'user' (relative to NTUSER.DAT) or 'machine'; (None, None) if unusable.
    A REGISTRY_KEY is already a glob ("...\\TypedURLs\\*" = everything under it); a plain key gets "\\*".
    """
    if value is None and key.endswith("*"):
        key, _, tail = key.rpartition("\\")             # "...\Run*" keeps "Run*" as its last part
    else:
        tail = "*" if value is None else (value or "@")  # "@" is the default value
    user = _USER_HIVE.match(key)
    if user:
        rest = _expand(key[user.end():])
        return ("user", rest + "\\" + tail) if rest else (None, None)
    if key.upper().startswith("HKEY_USERS\\"):           # %%users.sid%%_Classes (UsrClass.dat): not read
        return None, None
    key = re.sub(r"(?i)\\CurrentControlSet\\", r"\\ControlSet001\\", key)
    key = re.sub(r"(?i)^HKEY_CLASSES_ROOT\\", r"HKEY_LOCAL_MACHINE\\Software\\Classes\\", key)
    key = _expand(key)
    return ("machine", key + "\\" + tail) if key else (None, None)


def _doc(text: str) -> str:
    text = " ".join(str(text or "").split())
    sentences = re.split(r"(?<=\.)\s", text)
    short = " ".join(sentences[:2])
    return short if len(short) <= 240 else short[:237] + "..."


def convert(definitions: list) -> list:
    """Windows entries {name, doc, aliases, files, registry, user_registry, includes, url}."""
    out = []
    for d in definitions:
        files, registry, user_registry, includes = [], [], [], []
        for source in d.get("sources") or []:
            if not _windows(source, d):
                continue
            attrs = source.get("attributes") or {}
            kind = source.get("type")
            if kind in ("FILE", "PATH", "DIRECTORY"):
                files += [p for p in (convert_path(p) for p in attrs.get("paths") or []) if p]
            elif kind == "REGISTRY_KEY":
                pairs = [convert_key(k) for k in attrs.get("keys") or []]
            elif kind == "REGISTRY_VALUE":
                pairs = [convert_key(kv.get("key", ""), kv.get("value", "")) for kv in attrs.get("key_value_pairs") or []]
            elif kind == "ARTIFACT_GROUP":
                includes += list(attrs.get("names") or [])
            if kind in ("REGISTRY_KEY", "REGISTRY_VALUE"):
                registry += [g for k, g in pairs if k == "machine"]
                user_registry += [g for k, g in pairs if k == "user"]
        if not (files or registry or user_registry or includes):
            continue
        entry = {"name": d["name"], "doc": _doc(d.get("doc"))}
        if d.get("aliases"):
            entry["aliases"] = list(d["aliases"])
        for key, values in (("files", files), ("registry", registry), ("user_registry", user_registry),
                            ("includes", includes)):
            if values:
                entry[key] = list(dict.fromkeys(values))
        if d.get("urls"):
            entry["url"] = d["urls"][0]
        out.append(entry)
    return out


@functools.lru_cache(maxsize=1)
def entries() -> list:
    try:
        with open(DATA_FILE, encoding="utf-8") as f:
            return (yaml.safe_load(f) or {}).get("entries") or []
    except FileNotFoundError:
        return []


def _words(text: str) -> set:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text or ""))       # CamelCase names
    return set(re.findall(r"[a-z0-9]+", text.lower()))


_STOP = {"the", "a", "an", "of", "for", "in", "on", "and", "or", "to", "where", "is", "are", "file", "files",
         "windows", "data", "stored", "store", "kept", "location", "locations"}


def _collect(entry: dict) -> list:
    """Ready-to-use collections for an entry."""
    out = []
    if entry.get("files"):
        out.append({"artifact": "Windows.Search.FileFinder", "parameters": {"SearchFilesGlobTable": entry["files"]}})
    if entry.get("registry"):
        out.append({"artifact": "Windows.Search.FileFinder",
                    "parameters": {"SearchFilesGlobTable": entry["registry"], "Accessor": "registry"}})
    for key_glob in (entry.get("user_registry") or [])[:3]:
        out.append({"artifact": "Windows.Registry.NTUser", "parameters": {"KeyGlob": key_glob}})
    return out


def search(keyword: str, limit: int = 6) -> list:
    """Best matching entries for a keyword, each with ready-to-use collections."""
    wanted = [w for w in _words(keyword) if w not in _STOP] or list(_words(keyword))
    scored = []
    for entry in entries():
        name = _words(entry["name"]) | _words(" ".join(entry.get("aliases") or []))
        doc = _words(entry.get("doc"))
        paths = " ".join(entry.get("files", []) + entry.get("registry", []) + entry.get("user_registry", [])).lower()
        score = sum(3 if w in name else 2 if w in doc else 1 if w in paths else 0 for w in wanted)
        if score and any(w in name or w in doc for w in wanted):
            scored.append((score, -len(entry["name"]), entry))
    scored.sort(key=lambda s: (s[0], s[1]), reverse=True)
    results = []
    for _, _, entry in scored[:limit]:
        item = {"name": entry["name"], "what": entry["doc"], "collect": _collect(entry)}
        if len(entry.get("user_registry") or []) > 3:
            item["more_user_keys"] = entry["user_registry"][3:]
        if entry.get("includes"):
            item["see_also"] = entry["includes"]
        results.append(item)
    return results


# ---------------------------------------------------------------- import
def import_from(checkout: str) -> int:
    """Converts a checkout of ForensicArtifacts/artifacts into knowledge_data/forensic_artifacts.yaml."""
    data_dir = os.path.join(checkout, "artifacts", "data")
    definitions = []
    for name in sorted(os.listdir(data_dir)):
        if name.endswith(".yaml"):
            with open(os.path.join(data_dir, name), encoding="utf-8") as f:
                definitions += [d for d in yaml.safe_load_all(f) if d]
    try:
        commit = subprocess.run(["git", "-C", checkout, "rev-parse", "HEAD"], capture_output=True, text=True,
                                check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"
    converted = convert(definitions)
    header = (f"# Generated by `python -m copilot.forensic_artifacts import` from ForensicArtifacts/artifacts\n"
              f"# (https://github.com/ForensicArtifacts/artifacts, commit {commit}), Apache License 2.0:\n"
              f"# see forensic_artifacts.LICENSE. Do not edit by hand; re-run the import instead.\n")
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.safe_dump({"source": "https://github.com/ForensicArtifacts/artifacts", "commit": commit,
                        "entries": converted}, f, sort_keys=False, allow_unicode=True, width=200)
    shutil.copyfile(os.path.join(checkout, "LICENSE"), LICENSE_FILE)
    entries.cache_clear()
    return len(converted)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] != "import":
        print("usage: python -m copilot.forensic_artifacts import <checkout of ForensicArtifacts/artifacts>")
        return 2
    print(f"{import_from(argv[1])} Windows entries written to {DATA_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
