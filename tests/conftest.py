import os
import sys
import tempfile

import pytest

# Keep the import-time global database out of the working tree.
os.environ.setdefault("DFIR_CASE_DIR", tempfile.mkdtemp(prefix="dfir_test_"))
os.environ.setdefault("DFIR_CASE_FILE", os.path.join(os.path.dirname(__file__), "no_such_case.yaml"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from copilot import collection, tools  # noqa: E402
from copilot.case_config import case_config  # noqa: E402
from copilot.database import CaseDatabase  # noqa: E402

CLIENT = "C.1a2b3c4d5e6f7a8b"


class FakeVQL:
    """Answers the collection queries; records every (query, env) it receives."""

    def __init__(self, states=("FINISHED",), rows=None, flow_error="", schedule_fails=False):
        self.states = list(states)
        self.rows = rows if rows is not None else {"Generic.Client.Info/BasicInformation": [{"Hostname": "WS01"}]}
        self.flow_error = flow_error
        self.schedule_fails = schedule_fails
        self.calls = []

    def run_vql(self, query, env=None, timeout=None):
        self.calls.append((query, dict(env or {})))
        if "collect_client" in query:
            if self.schedule_fails:
                return {"results": [], "log": "artifact not found", "error": None}
            return {"results": [{"flow": {"flow_id": "F.TEST1"}}], "log": ""}
        if "FROM flows(" in query:
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return {"results": [{"state": state, "status": self.flow_error,
                                 "artifacts_with_results": list(self.rows) if state == "FINISHED" else []}],
                    "log": ""}
        if "FROM clients(" in query:
            return {"results": [{"hostname": "WS01"}], "log": ""}
        return {"results": [], "log": ""}

    def iter_rows(self, query, env=None, logs=None, timeout=None):
        self.calls.append((query, dict(env or {})))
        yield from self.rows.get(env["Artifact"], [])


@pytest.fixture
def case(tmp_path, monkeypatch):
    """Fresh database and a case pinned to CLIENT, patched into every module."""
    db = CaseDatabase(str(tmp_path))
    for module in (collection, tools):
        monkeypatch.setattr(module, "case_db", db)
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT}})
    return db
