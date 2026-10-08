"""
Local accounts for the Streamlit app. Works offline: no identity provider needed.

Users live in auth.yaml (DFIR_AUTH_FILE), git-ignored, with salted PBKDF2-SHA256 hashes
(standard library only). Manage them on the server:

    python -m copilot.auth add <username>      # asks for the password twice
    python -m copilot.auth remove <username>
    python -m copilot.auth list

With no users configured the app runs open (for local testing) and says so; set
DFIR_REQUIRE_LOGIN=1 on a server so it refuses to run open instead.
"""
import base64
import getpass
import hashlib
import hmac
import os
import re
import secrets
import sys
import time

import yaml

ITERATIONS = 600_000
MAX_FAILURES = 5          # per username, then locked for LOCKOUT_SECONDS
LOCKOUT_SECONDS = 300
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

_failures = {}            # username -> [timestamps of recent failures] (process-wide)


def auth_file() -> str:
    return os.environ.get("DFIR_AUTH_FILE", "auth.yaml")


def _load() -> dict:
    try:
        with open(auth_file(), encoding="utf-8") as f:
            return (yaml.safe_load(f) or {}).get("users", {}) or {}
    except FileNotFoundError:
        return {}


def _save(users: dict):
    path = auth_file()
    with open(path, "w", encoding="utf-8") as f:
        f.write("# DFIR Copilot accounts. Manage with: python -m copilot.auth add|remove|list\n")
        yaml.safe_dump({"users": users}, f, sort_keys=True)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def _check(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, digest = stored.split("$")
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), base64.b64decode(salt), int(iterations))
    return hmac.compare_digest(actual, base64.b64decode(digest))


def configured() -> bool:
    return bool(_load())


def is_user(username: str) -> bool:
    """The account still exists (removing it on the server ends its open sessions)."""
    return username in _load()


def login_required() -> bool:
    return configured() or os.environ.get("DFIR_REQUIRE_LOGIN", "").lower() in ("1", "true", "yes")


def locked_for(username: str) -> int:
    """Seconds the username is still locked after too many failures (0 = not locked)."""
    now = time.time()
    recent = [t for t in _failures.get(username, []) if now - t < LOCKOUT_SECONDS]
    _failures[username] = recent
    if len(recent) >= MAX_FAILURES:
        return int(LOCKOUT_SECONDS - (now - recent[0])) + 1
    return 0


def verify(username: str, password: str) -> bool:
    """True if the credentials are right and the account isn't locked. Failures are counted."""
    username = (username or "").strip()
    if locked_for(username):
        return False
    stored = _load().get(username, {}).get("hash", "")
    if stored:
        ok = _check(password or "", stored)
    else:
        # Same work as a real check, so timing doesn't reveal which usernames exist.
        hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), b"\0" * 16, ITERATIONS)
        ok = False
    if ok:
        _failures.pop(username, None)
    else:
        _failures.setdefault(username, []).append(time.time())
    return ok


def add_user(username: str, password: str):
    if not USERNAME_RE.match(username or ""):
        raise ValueError("Username: 1-64 letters, digits, '.', '_' or '-'.")
    if len(password or "") < 12:
        raise ValueError("Password: at least 12 characters.")
    users = _load()
    users[username] = {"hash": hash_password(password)}
    _save(users)


def remove_user(username: str) -> bool:
    users = _load()
    if username not in users:
        return False
    del users[username]
    _save(users)
    return True


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("add", "remove", "list"):
        print(__doc__)
        return 1
    if argv[0] == "list":
        users = sorted(_load())
        print("\n".join(users) if users else "No users configured (the app runs without login).")
        return 0
    if len(argv) != 2:
        print(f"Usage: python -m copilot.auth {argv[0]} <username>")
        return 1
    if argv[0] == "remove":
        print("Removed." if remove_user(argv[1]) else "No such user.")
        return 0
    password = getpass.getpass("Password (12+ characters): ")
    if password != getpass.getpass("Repeat password: "):
        print("Passwords don't match.")
        return 1
    try:
        add_user(argv[1], password)
    except ValueError as e:
        print(e)
        return 1
    print(f"User '{argv[1]}' saved in {os.path.abspath(auth_file())}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
