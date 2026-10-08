import os
import stat

import pytest

from copilot import auth

PASSWORD = "correct horse battery"


def test_password_is_stored_hashed_and_verifies(monkeypatch):
    auth.add_user("alice", PASSWORD)
    text = open(auth.auth_file(), encoding="utf-8").read()
    assert PASSWORD not in text and "pbkdf2_sha256$1000$" in text
    assert auth.verify("alice", PASSWORD)
    assert not auth.verify("alice", PASSWORD + "x")
    assert not auth.verify("mallory", PASSWORD)
    assert not auth.verify("alice", "")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_account_file_is_private():
    auth.add_user("alice", PASSWORD)
    assert stat.S_IMODE(os.stat(auth.auth_file()).st_mode) == 0o600


def test_same_password_gets_different_salts():
    assert auth.hash_password(PASSWORD) != auth.hash_password(PASSWORD)


def test_lockout_after_repeated_failures(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    auth.add_user("alice", PASSWORD)
    for _ in range(auth.MAX_FAILURES):
        assert not auth.verify("alice", "wrong password!")
    assert auth.locked_for("alice") > 0
    assert not auth.verify("alice", PASSWORD)            # even the right password, while locked
    assert auth.locked_for("bob") == 0                   # per account
    now[0] += auth.LOCKOUT_SECONDS + 1
    assert auth.verify("alice", PASSWORD)
    assert auth.locked_for("alice") == 0


def test_add_validates_and_remove(monkeypatch):
    with pytest.raises(ValueError, match="at least 12"):
        auth.add_user("alice", "short")
    with pytest.raises(ValueError, match="Username"):
        auth.add_user("al ice", PASSWORD)
    assert not auth.configured() and not auth.login_required()
    auth.add_user("alice", PASSWORD)
    assert auth.configured() and auth.login_required() and auth.is_user("alice")
    assert auth.remove_user("alice") and not auth.remove_user("alice")
    assert not auth.is_user("alice")


def test_login_can_be_required_before_any_account_exists(monkeypatch):
    monkeypatch.setenv("DFIR_REQUIRE_LOGIN", "1")
    assert auth.login_required() and not auth.configured()


def test_cli(monkeypatch, capsys):
    answers = iter([PASSWORD, PASSWORD, PASSWORD, "different password"])
    monkeypatch.setattr(auth.getpass, "getpass", lambda prompt="": next(answers))
    assert auth.main(["add", "alice"]) == 0
    assert auth.main(["add", "bob"]) == 1                # passwords don't match
    assert auth.main(["list"]) == 0
    assert auth.main(["remove", "alice"]) == 0
    assert auth.main(["frobnicate"]) == 1
    out = capsys.readouterr().out
    assert "User 'alice' saved" in out and "don't match" in out and "\nalice\n" in out and "Removed." in out
