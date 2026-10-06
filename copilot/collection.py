"""
Collecting Velociraptor artifacts from the case's dead-disk client into the case database.

Every user- or LLM-supplied value (client ID, artifact name, parameters, flow ID)
is passed to Velociraptor as a VQLEnv variable and referenced by name in the
query. Nothing is ever formatted into the VQL text.

Variable names carry a `Dfir` prefix: VQL resolves built-in names first, so a
variable called e.g. `Artifact` silently becomes the Artifact plugin instead.
"""
import json
import re
import time
from datetime import datetime, timezone

from copilot.case_config import case_config
from copilot.database import case_db
from copilot.vql_client import get_vql, VQLError

# Parameters go in `spec` ({"Artifact.Name": {"Param": "value"}}): the form current
# Velociraptor versions require. The older `env=` form is rejected by them.
SCHEDULE_VQL = (
    "SELECT collect_client(client_id=DfirClientId, artifacts=DfirArtifact, "
    "spec=parse_json(data=DfirSpec)) AS flow FROM scope()"
)
POLL_VQL = (
    "SELECT state, status, total_collected_rows, artifacts_with_results "
    "FROM flows(client_id=DfirClientId, flow_id=DfirFlowId)"
)
SOURCE_VQL = "SELECT * FROM source(client_id=DfirClientId, flow_id=DfirFlowId, artifact=DfirArtifact)"
HOSTNAME_VQL = "SELECT os_info.hostname AS hostname FROM clients(client_id=DfirClientId)"

POLL_INTERVAL = 2


class CollectionError(Exception):
    """A collection can't be started or tracked; the message is safe to show the LLM."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def encode_params(params: dict) -> dict:
    """
    Artifact parameters are strings in Velociraptor. Convert Python values
    to the string forms artifacts expect: bools to Y/N, lists/dicts to JSON.
    """
    encoded = {}
    for key, value in (params or {}).items():
        if not isinstance(key, str) or not key:
            raise CollectionError(f"Invalid parameter name: {key!r}")
        if isinstance(value, bool):
            encoded[key] = "Y" if value else "N"
        elif isinstance(value, (list, dict)):
            encoded[key] = json.dumps(value)
        elif value is None:
            encoded[key] = ""
        else:
            encoded[key] = str(value)
    return encoded


def _target_client() -> str:
    error = case_config.client_id_error
    if error:
        raise CollectionError(error)
    return case_config.client_id


def _check_artifact(artifact: str):
    if not case_config.is_artifact_allowed(artifact):
        raise CollectionError(
            f"Artifact '{artifact}' is not allowed for this case. Allowed patterns: "
            f"{', '.join(case_config.artifact_allowlist)}. The investigator can extend "
            f"`artifacts.allow` in {case_config.path}."
        )


# Progress chatter in the query log that isn't useful to the agent or investigator.
_LOG_NOISE = re.compile(r"^(Starting query execution\.?|Time \d+: .*Sending response part.*)$")


def _clean_log(log: str) -> str:
    lines = [l for l in (log or "").splitlines() if l.strip() and not _LOG_NOISE.match(l.strip())]
    return "\n".join(lines)


def _run(vql, query: str, env: dict) -> tuple:
    res = vql.run_vql(query, env=env)
    log = _clean_log(res.get("log", ""))
    if res.get("error"):
        raise CollectionError(f"Velociraptor call failed: {res['error']}\n{log}".strip())
    return res.get("results", []), log


def schedule(artifact: str, params: dict = None, vql=None) -> str:
    """Starts a collection on the case client and returns its flow ID."""
    vql = vql or get_vql()
    client_id = _target_client()
    _check_artifact(artifact)
    encoded = encode_params(params)

    env = {"DfirClientId": client_id, "DfirArtifact": artifact, "DfirSpec": json.dumps({artifact: encoded})}
    rows, log = _run(vql, SCHEDULE_VQL, env)
    case_db.log_query("collect_artifact", f"{SCHEDULE_VQL} -- env={json.dumps(env)}", len(rows), artifact)

    flow = (rows[0].get("flow") if rows else None) or {}
    flow_id = flow.get("flow_id")
    if not flow_id:
        raise CollectionError(f"Velociraptor did not start a flow for '{artifact}'.\n{log}".strip())

    case_db.upsert_collection(flow_id, client_id=client_id, artifact=artifact,
                              parameters=json.dumps(encoded), state="RUNNING",
                              requested_at=_now())
    return flow_id


def poll(flow_id: str, vql=None) -> dict:
    """Returns the flow's current state from the server and records it."""
    vql = vql or get_vql()
    known = case_db.get_collection(flow_id)
    if not known:
        raise CollectionError(f"Flow '{flow_id}' was not started by this case.")

    rows, log = _run(vql, POLL_VQL, {"DfirClientId": known["client_id"], "DfirFlowId": flow_id})
    if not rows:
        raise CollectionError(f"Flow '{flow_id}' not found on the server.\n{log}".strip())

    row = rows[0]
    state = row.get("state") or "UNKNOWN"
    error = (row.get("status") or "") if state == "ERROR" else ""
    case_db.upsert_collection(flow_id, state=state, error=error)
    return {"state": state, "error": error,
            "artifacts_with_results": row.get("artifacts_with_results") or [],
            "total_collected_rows": row.get("total_collected_rows") or 0}


def ingest(flow_id: str, artifacts_with_results: list, vql=None) -> int:
    """Streams a finished flow's results into the case database (once per flow)."""
    vql = vql or get_vql()
    known = case_db.get_collection(flow_id)
    if known.get("ingested"):
        return known.get("rows_ingested") or 0

    client_id = known["client_id"]
    hostname = "Unknown"
    try:
        host_rows, _ = _run(vql, HOSTNAME_VQL, {"DfirClientId": client_id})
        if host_rows and host_rows[0].get("hostname"):
            hostname = host_rows[0]["hostname"]
    except CollectionError:
        pass

    total = 0
    for sub_artifact in artifacts_with_results:
        logs = []
        env = {"DfirClientId": client_id, "DfirFlowId": flow_id, "DfirArtifact": sub_artifact}
        try:
            rows = vql.iter_rows(SOURCE_VQL, env=env, logs=logs)
            added = case_db.ingest_artifact_results(rows, sub_artifact, hostname, client_id)
        except VQLError as e:
            raise CollectionError(f"Reading results of {sub_artifact} failed: {e}") from e
        total += added
        case_db.log_query("ingest", f"{SOURCE_VQL} -- env={json.dumps(env)}", added, sub_artifact)

    case_db.upsert_collection(flow_id, ingested=1, rows_ingested=total, finished_at=_now())
    return total


def _summary(flow_id: str, status: dict, rows_ingested: int = None) -> dict:
    known = case_db.get_collection(flow_id)
    summary = {
        "flow_id": flow_id,
        "artifact": known.get("artifact"),
        "state": status["state"],
    }
    if status["state"] == "FINISHED":
        summary["sub_artifacts_with_results"] = status["artifacts_with_results"]
        summary["new_rows_ingested"] = rows_ingested
        if not status["artifacts_with_results"]:
            summary["note"] = "Collection finished but returned no rows."
    elif status["state"] == "ERROR":
        summary["error"] = status["error"]
        summary["note"] = "Collection failed on the client. Nothing was ingested."
    else:
        summary["note"] = (f"Still {status['state']}. Nothing has been ingested yet. "
                           f"Call check_collection('{flow_id}') later; do not treat this as 'no results'.")
    return summary


def check(flow_id: str, vql=None) -> dict:
    """Polls once; ingests if the flow has finished."""
    vql = vql or get_vql()
    status = poll(flow_id, vql)
    rows = None
    if status["state"] == "FINISHED":
        rows = ingest(flow_id, status["artifacts_with_results"], vql)
    return _summary(flow_id, status, rows)


def collect(artifact: str, params: dict = None, wait_seconds: int = None, vql=None,
            sleep=time.sleep) -> dict:
    """Schedules a collection and waits up to `wait_seconds` for it to finish."""
    vql = vql or get_vql()
    wait = case_config.collection_wait_seconds if wait_seconds is None else wait_seconds
    flow_id = schedule(artifact, params, vql)

    deadline = time.monotonic() + wait
    while True:
        status = poll(flow_id, vql)
        if status["state"] != "RUNNING" or time.monotonic() >= deadline:
            break
        sleep(POLL_INTERVAL)

    rows = None
    if status["state"] == "FINISHED":
        rows = ingest(flow_id, status["artifacts_with_results"], vql)
    return _summary(flow_id, status, rows)
