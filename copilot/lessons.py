"""
Lessons learned: knowledge the agent and the investigators add while working.

The agent PROPOSES a lesson (propose_lesson tool) when it verified something reusable, e.g.
"Windows.System.Services needs WMI and returns nothing from disk images". The proposal goes
through the approval queue like any other change. Evidence is attacker-written, so nothing is
ever learned without a person approving it.

Lessons are shared by every case and every user on this server, so with sign-in a lesson
approved by a non-admin is stored as PROPOSED until an admin accepts it. Without sign-in (or in
the CLI, which runs on the server) the approver is trusted. Only ACTIVE lessons reach the agent:
next to the built-in knowledge in dfir_guide / describe_artifact, and an artifact a lesson marks
as unusable on disk images is refused before anyone is asked to approve its collection.

Stored in learned_knowledge.yaml (server.yaml knowledge.learned_file, or DFIR_LEARNED_FILE),
git-ignored. Manage on the server:
    python -m copilot.lessons list
    python -m copilot.lessons accept <id>
    python -m copilot.lessons remove <id>
"""
import fnmatch
import os
import secrets
import sys
import tempfile
import threading
from datetime import datetime, timezone

import yaml

from copilot import settings

MAX_TOPIC = 100
MAX_TEXT = 600
_lock = threading.Lock()


class LessonError(Exception):
    """The lesson can't be saved; the message is safe to show to the agent or user."""


def learned_file() -> str:
    return str(settings.get("knowledge", "learned_file", "DFIR_LEARNED_FILE", "learned_knowledge.yaml"))


_cache = {"key": None, "lessons": []}


def _load() -> list:
    path = learned_file()
    try:
        key = (os.path.abspath(path), os.path.getmtime(path), os.path.getsize(path))
    except OSError:
        return []
    if _cache["key"] != key:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        lessons = data.get("lessons") if isinstance(data, dict) else None
        _cache.update(key=key, lessons=[l for l in lessons or [] if isinstance(l, dict) and l.get("id")])
    return [dict(l) for l in _cache["lessons"]]


def _save(lessons: list):
    path = os.path.abspath(learned_file())
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".learned-", suffix=".yaml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("# Lessons learned by DFIR Copilot. Manage with: python -m copilot.lessons list|accept|remove\n")
        yaml.safe_dump({"lessons": lessons}, f, sort_keys=False, allow_unicode=True)
    os.replace(tmp, path)           # never a half-written file, even with several sessions


def all_lessons() -> list:
    return _load()


def active() -> list:
    return [l for l in _load() if l.get("status") == "active"]


def proposed() -> list:
    return [l for l in _load() if l.get("status") == "proposed"]


def check(topic: str, text: str, from_agent: bool = False) -> tuple:
    """Cleaned (topic, text); LessonError if unusable. Agent lessons must not carry case details."""
    topic = " ".join(str(topic or "").split())
    text = " ".join(str(text or "").split())
    if not topic or len(topic) > MAX_TOPIC:
        raise LessonError(f"The topic must be 1-{MAX_TOPIC} characters (an artifact name, a playbook or a subject).")
    if len(text) < 10 or len(text) > MAX_TEXT:
        raise LessonError(f"The lesson must be 10-{MAX_TEXT} characters.")
    if from_agent:
        from copilot.iocs import extract_iocs
        found = {k: v for k, v in extract_iocs(f"{topic} {text}").items() if v and k in ("ips", "hashes", "domains")}
        # Artifact and stream names (Windows.NTFS.MFT, Zone.Identifier) look like domains: only
        # real-looking ones count (a common or two-letter top-level domain).
        found["domains"] = [d for d in found.get("domains", []) if _real_domain(d)]
        found = {k: v for k, v in found.items() if v}
        if found:
            raise LessonError("Lessons are shared by every case, so they must be general: leave out case details "
                              f"such as {', '.join(sum(found.values(), []))[:200]}.")
    return topic, text


_TLDS = {"com", "net", "org", "info", "biz", "io", "gov", "edu", "mil", "int", "xyz", "top", "online", "site",
         "club", "live", "app", "dev", "cloud", "tech", "onion", "ru", "cn", "tk", "ml", "ga", "cf", "gq", "pw", "cc"}


def _real_domain(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in _TLDS or (len(tld) == 2 and tld.isalpha())


def _trusted(approver: str) -> bool:
    """No sign-in in this session (CLI, or the app without accounts), or an admin."""
    from copilot import auth, session
    if session.current_user() is None:
        return True
    return bool(approver) and auth.is_admin(approver)


def add(topic: str, text: str, unusable_on_images: bool = False, source: str = "investigator",
        approver: str = None, auto_approved: bool = False, case: str = "") -> dict:
    """Saves a lesson: active if a trusted person approved it, else proposed for an admin."""
    topic, text = check(topic, text, from_agent=(source == "agent"))
    lesson = {
        "id": secrets.token_hex(4),
        "topic": topic,
        "text": text,
        "unusable_on_images": bool(unusable_on_images),
        "status": "active" if (not auto_approved and _trusted(approver)) else "proposed",
        "source": source,
        "case": case,
        "approved_by": approver or ("auto" if auto_approved else ""),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with _lock:
        lessons = _load()
        duplicate = next((l for l in lessons if l["topic"].lower() == topic.lower()
                          and l["text"].lower() == text.lower()), None)
        if duplicate:
            return duplicate
        lessons.append(lesson)
        _save(lessons)
    return lesson


def _find(lessons: list, lesson_id: str) -> dict:
    lesson = next((l for l in lessons if l["id"] == (lesson_id or "").strip()), None)
    if not lesson:
        raise LessonError(f"No lesson '{lesson_id}'.")
    return lesson


def accept(lesson_id: str, approver: str = None) -> dict:
    """An admin (or anyone without sign-in) makes a proposed lesson active."""
    if not _trusted(approver):
        raise LessonError("Only an admin can accept lessons: they change the agent for every case.")
    with _lock:
        lessons = _load()
        lesson = _find(lessons, lesson_id)
        lesson["status"] = "active"
        lesson["approved_by"] = approver or lesson.get("approved_by") or ""
        _save(lessons)
    return lesson


def remove(lesson_id: str, approver: str = None) -> dict:
    if not _trusted(approver):
        raise LessonError("Only an admin can remove lessons.")
    with _lock:
        lessons = _load()
        lesson = _find(lessons, lesson_id)
        lessons.remove(lesson)
        _save(lessons)
    return lesson


def _matches(lesson: dict, name: str) -> bool:
    topic, name = lesson["topic"].lower(), (name or "").split("/", 1)[0].lower()
    return bool(name) and (fnmatch.fnmatchcase(name, topic) or name == topic or
                           (topic.endswith(".") and name.startswith(topic)))


def for_topic(name: str) -> list:
    """Active lessons about an artifact (exact name or glob topic) or another topic."""
    return [l for l in active() if _matches(l, name)]


def unusable(artifact: str) -> dict:
    """The active lesson that marks this artifact as not working on disk images, if any."""
    return next((l for l in for_topic(artifact) if l.get("unusable_on_images")), None)


def summary(lesson: dict) -> str:
    flag = " [does not work on disk images]" if lesson.get("unusable_on_images") else ""
    return f"{lesson['topic']}{flag}: {lesson['text']}"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("list", "accept", "remove"):
        print(__doc__)
        return 1
    if argv[0] == "list":
        lessons = _load()
        if not lessons:
            print(f"No lessons yet ({os.path.abspath(learned_file())}).")
        for l in lessons:
            print(f"{l['id']}  [{l['status']}]  {summary(l)}  (approved by {l.get('approved_by') or '-'}, "
                  f"case {l.get('case') or '-'}, {l.get('created', '')})")
        return 0
    if len(argv) != 2:
        print(f"Usage: python -m copilot.lessons {argv[0]} <id>")
        return 1
    try:
        lesson = accept(argv[1]) if argv[0] == "accept" else remove(argv[1])
    except LessonError as e:
        print(e)
        return 1
    print(f"{'Accepted' if argv[0] == 'accept' else 'Removed'}: {summary(lesson)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
