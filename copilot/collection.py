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
# Named sources ("Artifact/Source") are addressed with a separate `source` argument.
SOURCE_NAMED_VQL = ("SELECT * FROM source(client_id=DfirClientId, flow_id=DfirFlowId, "
                    "artifact=DfirArtifact, source=DfirSource)")
HOSTNAME_VQL = "SELECT os_info.hostname AS hostname FROM clients(client_id=DfirClientId)"

POLL_INTERVAL = 2

# Flow states after which nothing more will happen. Everything else (RUNNING,
# WAITING, IN_PROGRESS, UNRESPONSIVE... depending on the Velociraptor version)
# means "not done yet".
TERMINAL_STATES = {"FINISHED", "ERROR", "CANCELLED"}


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


def _source_query(client_id: str, flow_id: str, sub_artifact: str) -> tuple:
    if "/" in sub_artifact:
        artifact, source = sub_artifact.split("/", 1)
        return SOURCE_NAMED_VQL, {"DfirClientId": client_id, "DfirFlowId": flow_id,
                                  "DfirArtifact": artifact, "DfirSource": source}
    return SOURCE_VQL, {"DfirClientId": client_id, "DfirFlowId": flow_id, "DfirArtifact": sub_artifact}


def ingest(flow_id: str, status: dict, vql=None) -> dict:
    """
    Streams a finished flow's results into the case database. Returns
    {"rows_read": n, "new_rows": m}. The flow is only marked ingested when the
    rows Velociraptor reports could actually be read, so a failed read is retried
    by the next check_collection instead of being remembered as "0 rows".
    """
    vql = vql or get_vql()
    known = case_db.get_collection(flow_id)
    if known.get("ingested"):
        return {"rows_read": None, "new_rows": known.get("rows_ingested") or 0, "already_ingested": True}

    client_id = known["client_id"]
    hostname = "Unknown"
    try:
        host_rows, _ = _run(vql, HOSTNAME_VQL, {"DfirClientId": client_id})
        if host_rows and host_rows[0].get("hostname"):
            hostname = host_rows[0]["hostname"]
    except CollectionError:
        pass

    sub_artifacts = list(status["artifacts_with_results"])
    if not sub_artifacts and status["total_collected_rows"]:
        # Rows exist but the flow didn't list where; try the artifact itself.
        sub_artifacts = [known["artifact"]]

    read = 0
    new = 0
    for sub_artifact in sub_artifacts:
        query, env = _source_query(client_id, flow_id, sub_artifact)
        logs = []
        counted = [0]

        def counting(rows):
            for row in rows:
                counted[0] += 1
                yield row

        try:
            added = case_db.ingest_artifact_results(
                counting(vql.iter_rows(query, env=env, logs=logs)), sub_artifact, hostname, client_id)
        except VQLError as e:
            raise CollectionError(f"Reading results of {sub_artifact} failed: {e}") from e
        read += counted[0]
        new += added
        case_db.log_query("ingest", f"{query} -- env={json.dumps(env)}", counted[0], sub_artifact)
        if not counted[0] and _clean_log("\n".join(logs)):
            case_db.upsert_collection(flow_id, error=_clean_log("\n".join(logs))[:2000])

    complete = read > 0 or not status["total_collected_rows"]
    if complete:
        case_db.upsert_collection(flow_id, ingested=1, rows_ingested=new, finished_at=_now())
    return {"rows_read": read, "new_rows": new}


def _summary(flow_id: str, status: dict, result: dict = None) -> dict:
    known = case_db.get_collection(flow_id)
    summary = {
        "flow_id": flow_id,
        "artifact": known.get("artifact"),
        "state": status["state"],
    }
    if status["state"] == "FINISHED":
        total = status["total_collected_rows"]
        summary["rows_collected_by_velociraptor"] = total
        summary["sub_artifacts_with_results"] = status["artifacts_with_results"]
        summary["rows_read"] = result.get("rows_read")
        summary["new_rows_ingested"] = result.get("new_rows")
        if result.get("already_ingested"):
            summary["note"] = "Already ingested earlier."
        elif not total:
            summary["note"] = ("Velociraptor collected 0 rows. The artifact found nothing on the image; on a "
                               "dead disk this can also mean its paths did not resolve through the remapping.")
        elif not result.get("rows_read"):
            summary["note"] = ("Velociraptor reports rows but none could be read back, so nothing was "
                               "ingested. This is a copilot problem, not an empty result; check_collection "
                               "will retry.")
            if known.get("error"):
                summary["read_log"] = known["error"]
        elif not result.get("new_rows"):
            summary["note"] = "All rows were already in the case database (collected before)."
    elif status["state"] in ("ERROR", "CANCELLED"):
        summary["error"] = status["error"]
        summary["note"] = f"Collection {status['state'].lower()}. Nothing was ingested."
    else:
        summary["note"] = (f"Still {status['state']}. Nothing has been ingested yet. "
                           f"Call check_collection('{flow_id}') later; do not treat this as 'no results'.")
    return summary


def check(flow_id: str, vql=None) -> dict:
    """Polls once; ingests if the flow has finished."""
    vql = vql or get_vql()
    status = poll(flow_id, vql)
    result = ingest(flow_id, status, vql) if status["state"] == "FINISHED" else None
    return _summary(flow_id, status, result)


def collect(artifact: str, params: dict = None, wait_seconds: int = None, vql=None,
            sleep=time.sleep) -> dict:
    """Schedules a collection and waits up to `wait_seconds` for it to finish."""
    vql = vql or get_vql()
    wait = case_config.collection_wait_seconds if wait_seconds is None else wait_seconds
    flow_id = schedule(artifact, params, vql)

    deadline = time.monotonic() + wait
    while True:
        status = poll(flow_id, vql)
        if status["state"] in TERMINAL_STATES or time.monotonic() >= deadline:
            break
        sleep(POLL_INTERVAL)

    result = ingest(flow_id, status, vql) if status["state"] == "FINISHED" else None
    return _summary(flow_id, status, result)
