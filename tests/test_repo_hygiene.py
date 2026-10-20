"""The repository never carries credentials or evidence, and its settings files are valid."""
import fnmatch
import os
import re
import subprocess

import pytest

from copilot import config_check

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Files that hold secrets, accounts or evidence: they belong next to the code, never in Git.
NEVER_TRACKED = ["api_client.yaml", "server.yaml", "auth.yaml", "learned_knowledge.yaml", ".streamlit/secrets.toml",
                 "*.writeback.yaml", "*.config.yaml", "*.pem", "*.key", ".env", "case_data/*", "cases/*/data/*",
                 "benchmark_results/*", "*.db", "*.db-wal", "*.E0[0-9]", "*.ad1", "*.mem", "*.vmem", "*.dmp",
                 "imagetest/*"]
SECRET_TEXT = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{24,}"), "an API key"),
    (re.compile(r"(?im)^\s*api_key:\s*[\"']?[A-Za-z0-9_\-]{20,}"), "an API key in settings"),
]


def _tracked() -> list:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("not a git checkout")
    return [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]


def test_no_secret_or_evidence_file_is_tracked():
    bad = [p for p in _tracked() if any(fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(os.path.basename(p), pat)
                                        for pat in NEVER_TRACKED)]
    assert bad == [], f"never commit these (secrets or evidence): {bad}"


def test_no_tracked_file_contains_a_key():
    found = []
    for path in _tracked():
        full = os.path.join(ROOT, path)
        if not os.path.isfile(full) or os.path.getsize(full) > 5_000_000:
            continue
        with open(full, "rb") as f:
            data = f.read()
        if b"\0" in data[:4096]:
            continue                                  # binary
        text = data.decode("utf-8", "replace")
        found += [f"{path}: {what}" for pattern, what in SECRET_TEXT if pattern.search(text)]
    assert found == [], f"remove these before committing: {found}"


def test_shipped_settings_files_are_valid():
    paths = [os.path.join(ROOT, "server.example.yaml"), os.path.join(ROOT, "case.yaml")]
    cases_root = os.path.join(ROOT, "cases")
    paths += [os.path.join(cases_root, d, "case.yaml") for d in sorted(os.listdir(cases_root))
              if os.path.isfile(os.path.join(cases_root, d, "case.yaml")) and not d.startswith("bench-")]
    problems = {os.path.relpath(p, ROOT): config_check.check_file(p) for p in paths}
    assert {p: v for p, v in problems.items() if v} == {}


def test_settings_problems_are_named_in_words():
    data = {"agent": {"max_step": 20, "max_tokens_per_turn": "lots", "approvals": {"collect": "sometimes"}},
            "colect": [], "scope": {"start_time": "2020-09-18T00:00:00Z", "clock_offset_minutes": 60}}
    problems = config_check.check(data, config_check.CASE_SCHEMA)
    assert "unknown setting 'agent.max_step' (did you mean 'max_steps'?): it is ignored" in problems
    assert "unknown setting 'colect' (did you mean 'collect'?): it is ignored" in problems
    assert "'agent.max_tokens_per_turn' should be a whole number, not 'lots'" in problems
    assert any("agent.approvals.collect" in p and "one of confirm" in p for p in problems)
    assert len(problems) == 4
    assert config_check.check({"llm": {"timeout": 1.5, "local": "yes"}}, config_check.SERVER_SCHEMA) == [
        "'llm.local' should be true or false, not 'yes'"]
