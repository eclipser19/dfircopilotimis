"""
DFIR knowledge base, loaded from copilot/knowledge_data/*.yaml:
  artifacts.yaml  — where each artifact's data lives, what it proves, verified parameter
                    names, tips, and whether it only works on a live system;
  event_ids.yaml  — what Windows event IDs mean (per log channel);
  playbooks.yaml  — for an investigation question, which sources to check.

Used by the report (artifact and event explanations are never written by the LLM),
by describe_artifact, by collection (live-only artifacts are refused on images) and
by the agent's dfir_guide tool. Extend the YAML files; no code changes needed.
"""
import fnmatch
import os
import re
from functools import lru_cache

import yaml

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge_data")
UNKNOWN = {"what": "Velociraptor artifact", "location": "—", "meaning": "See the artifact's description."}


@lru_cache(maxsize=None)
def _load(name: str):
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def artifacts() -> list:
    return _load("artifacts.yaml")


def event_ids() -> list:
    return _load("event_ids.yaml")


def playbooks() -> dict:
    return _load("playbooks.yaml")


def logon_type(value) -> str:
    try:
        return _load("logon_types.yaml").get(int(str(value).strip()), "")
    except (TypeError, ValueError):
        return ""


def artifact_info(source: str) -> dict:
    """Reference entry for an artifact or 'Artifact/Source' name (first matching pattern)."""
    artifact = source.split("/", 1)[0].lower()
    for entry in artifacts():
        if fnmatch.fnmatchcase(artifact, str(entry["pattern"]).lower()):
            return entry
    return UNKNOWN


def is_live_only(artifact: str) -> bool:
    return bool(artifact_info(artifact).get("live_only"))


def event_info(event_id, channel: str = "") -> dict:
    """
    Meaning of an event ID. IDs reused across logs are disambiguated by channel; an ID with
    a single entry is returned even without a channel. {} when unknown or ambiguous.
    """
    try:
        eid = int(str(event_id).strip())
    except (TypeError, ValueError):
        return {}
    candidates = [e for e in event_ids() if e["id"] == eid]
    if channel:
        ch = channel.lower()
        matching = [e for e in candidates if e["channel"].lower() in ch]
        if matching:
            return matching[0]
    return candidates[0] if len(candidates) == 1 else {}


def guide(topic: str) -> str:
    """Plain-text answer for the agent: a playbook, an event ID, or an artifact."""
    topic = (topic or "").strip()
    books = playbooks()
    key = topic.lower().replace(" ", "_").replace("-", "_")
    if key in books:
        book = books[key]
        return f"{book['question']}\n" + "\n".join(f"- {line}" for line in book["check"])

    m = re.match(r"(?i)^\s*(?:event(?:\s*id)?\s*:?\s*)?(\d+)\s*$", topic)
    if m:
        hits = [e for e in event_ids() if e["id"] == int(m.group(1))]
        if not hits:
            return f"Event ID {m.group(1)} is not in the reference."
        return "\n".join(f"{e['id']} ({e['channel']}): {e['meaning']}" + (f". {e['details']}" if e.get("details") else "")
                         for e in hits)

    name = topic.split(":", 1)[-1].strip() if topic.lower().startswith("artifact") else topic
    info = artifact_info(name)
    if info is not UNKNOWN:
        lines = [f"{name}: {info['what']}", f"Location: {info['location']}", f"Shows: {info['meaning']}"]
        if info.get("live_only"):
            lines.append("LIVE SYSTEM ONLY: returns nothing from a disk image.")
        if info.get("dead_disk_note"):
            lines.append(f"Disk images: {info['dead_disk_note']}")
        if info.get("params"):
            lines.append("Verified parameters: " + ", ".join(f"{k} ({v})" for k, v in info["params"].items()))
        lines += [f"Tip: {t}" for t in info.get("tips", [])]
        return "\n".join(lines)

    return ("Unknown topic. Playbooks: " + ", ".join(books) +
            ". Or ask for an event ID (e.g. '4624') or an artifact name (e.g. 'Windows.NTFS.MFT').")
