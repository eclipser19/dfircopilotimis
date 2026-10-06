import os
import sys
import tempfile

import pytest

# Keep the import-time global database out of the working tree.
os.environ.setdefault("DFIR_CASE_DIR", tempfile.mkdtemp(prefix="dfir_test_"))
os.environ.setdefault("DFIR_CASE_FILE", os.path.join(os.path.dirname(__file__), "no_such_case.yaml"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from copilot import collection, outputs, tools  # noqa: E402
from copilot.case_config import case_config  # noqa: E402
from copilot.database import CaseDatabase  # noqa: E402

CLIENT = "C.1a2b3c4d5e6f7a8b"


class FakeVQL:
    """Answers the collection queries; records every (query, env) it receives."""

    def __init__(self, states=("FINISHED",), rows=None, flow_error="", schedule_fails=False,
                 reported_rows=None, listed=None, flow_logs=None, artifact_params=None,
                 rejects_max_rows=False):
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
            return {"results": [{"flow": {"flow_id": "F.TEST1"}}], "log": ""}
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


@pytest.fixture
def case(tmp_path, monkeypatch):
    """Fresh database and a case pinned to CLIENT, patched into every module."""
    db = CaseDatabase(str(tmp_path))
    for module in (collection, tools, outputs):
        monkeypatch.setattr(module, "case_db", db)
    monkeypatch.setenv("DFIR_OUTPUT_DIR", str(tmp_path / "outputs"))
    monkeypatch.setattr(case_config, "data", {"velociraptor": {"client_id": CLIENT}})
    return db
