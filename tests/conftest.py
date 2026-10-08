import os
import sys
import tempfile

import pytest

# Keep the import-time global database out of the working tree.
os.environ.setdefault("DFIR_CASE_DIR", tempfile.mkdtemp(prefix="dfir_test_"))
os.environ.setdefault("DFIR_CASE_FILE", os.path.join(os.path.dirname(__file__), "no_such_case.yaml"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from copilot import approvals, session  # noqa: E402
from copilot.case_config import case_config  # noqa: E402
from copilot.database import CaseDatabase  # noqa: E402

CLIENT = "C.1a2b3c4d5e6f7a8b"


class FakeVQL:
    """Answers the collection queries; records every (query, env) it receives."""

    def __init__(self, states=("FINISHED",), rows=None, flow_error="", schedule_fails=False,
                 reported_rows=None, listed=None, flow_logs=None, artifact_params=None,
                 rejects_max_rows=False, unique_flows=False):
        self.states = list(states)
        self.rows = rows if rows is not None else {"Generic.Client.Info/BasicInformation": [{"Hostname": "WS01"}]}
        self.flow_error = flow_error
        self.schedule_fails = schedule_fails
        # What flows() claims, which can differ from what source() returns.
        self.reported_rows = reported_rows
        self.listed = listed
        self.flow_logs = flow_logs or []
        self.artifact_params = artifact_params or []
        self.rejects_max_rows = rejects_max_rows
        self.unique_flows = unique_flows     # a new flow ID per collection, like Velociraptor
        self.flows = 0
        self.calls = []

    def run_vql(self, query, env=None, timeout=None):
        self.calls.append((query, dict(env or {})))
        if "FROM artifact_definitions(" in query:
            return {"results": [{"parameters": [{"name": n} for n in self.artifact_params]}], "log": ""}
        if "collect_client" in query:
            if self.rejects_max_rows and "max_rows" in query:
                return {"results": [], "log": "collect_client: Unexpected arg max_rows"}
            if self.schedule_fails:
                return {"results": [], "log": "artifact not found", "error": None}
            self.flows += 1
            flow_id = f"F.TEST{self.flows}" if self.unique_flows else "F.TEST1"
            return {"results": [{"flow": {"flow_id": flow_id}}], "log": ""}
        if "FROM flows(" in query:
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            finished = state == "FINISHED"
            listed = self.listed if self.listed is not None else list(self.rows)
            total = self.reported_rows if self.reported_rows is not None else sum(map(len, self.rows.values()))
            return {"results": [{"state": state, "status": self.flow_error,
                                 "total_collected_rows": total if finished else 0,
                                 "artifacts_with_results": listed if finished else []}],
                    "log": ""}
        if "FROM flow_logs(" in query:
            return {"results": self.flow_logs, "log": ""}
        if "FROM clients(" in query:
            return {"results": [{"hostname": "WS01"}], "log": ""}
        return {"results": [], "log": ""}

    def iter_rows(self, query, env=None, logs=None, timeout=None):
        self.calls.append((query, dict(env or {})))
        name = env["DfirArtifact"] + ("/" + env["DfirSource"] if "DfirSource" in env else "")
        if "DfirSource" in env:
            assert "source=DfirSource" in query
        yield from self.rows.get(name, [])


@pytest.fixture(autouse=True)
def fresh_session(tmp_path, monkeypatch):
    """Every test gets its own process session (the CLI's), opened on an empty case in tmp_path."""
    monkeypatch.setattr(session, "_default", None)
    monkeypatch.setattr(session, "PROVIDER", None)
    monkeypatch.setenv("DFIR_CASE_DIR", str(tmp_path / "default_case"))
    yield
    if session._default is not None and session._default.db is not None:
        session._default.db.conn.close()      # the config stays: monkeypatch restores attributes on it


def use_db(monkeypatch, db):
    """Makes db the current session's case database."""
    current = session.default()
    current.db.conn.close()
    monkeypatch.setattr(current, "db", db)
    return db


@pytest.fixture
def case(tmp_path, monkeypatch):
    """Fresh database and a case pinned to CLIENT, as the session's active case."""
    db = use_db(monkeypatch, CaseDatabase(str(tmp_path)))
    monkeypatch.setenv("DFIR_OUTPUT_DIR", str(tmp_path / "outputs"))
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT}})
    return db


@pytest.fixture(autouse=True)
def no_approval_channel(monkeypatch):
    """Every test starts without an approval UI (the CLI test installs its own prompt)."""
    monkeypatch.setattr(approvals, "ASK", None)
    monkeypatch.setattr(approvals, "ACTOR", None)


@pytest.fixture(autouse=True)
def isolated_server_settings(tmp_path, monkeypatch):
    """No accounts and the default cloud endpoint, whatever the developer's shell or folder has."""
    from copilot import auth
    monkeypatch.setenv("DFIR_AUTH_FILE", str(tmp_path / "no_auth.yaml"))
    monkeypatch.setenv("DFIR_SETTINGS", str(tmp_path / "no_server.yaml"))
    monkeypatch.setenv("DFIR_LEARNED_FILE", str(tmp_path / "learned_knowledge.yaml"))
    for var in ("DFIR_REQUIRE_LOGIN", "DFIR_LLM_BASE_URL", "DFIR_LLM_MODEL", "DFIR_LLM_API_KEY", "DFIR_LLM_LOCAL",
                "DFIR_LLM_TIMEOUT", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(auth, "_failures", {})
    monkeypatch.setattr(auth, "ITERATIONS", 1000)       # fast hashing in tests


@pytest.fixture
def approve_all(monkeypatch):
    """The investigator approves every request (records them for assertions)."""
    asked = []
    monkeypatch.setattr(approvals, "ASK", lambda request: asked.append(request) or True)
    return asked
