"""
Collecting Velociraptor artifacts from the case's dead-disk client into the case database.

Every user- or LLM-supplied value (client ID, artifact name, parameters, flow ID)
is passed to Velociraptor as a VQLEnv variable and referenced by name in the
query. Nothing is ever formatted into the VQL text.

Variable names carry a `Dfir` prefix: VQL resolves built-in names first, so a
variable called e.g. `Artifact` silently becomes the Artifact plugin instead.
"""
import csv
import io
import json
import re
import time
from datetime import datetime, timezone

from copilot.case_config import case_config
from copilot.database import case_db
from copilot.vql_client import get_vql, VQLError

# Parameters go in `spec` ({"Artifact.Name": {"Param": "value"}}): the form current
# Velociraptor versions require. The older `env=` form is rejected by them.
# max_rows is our own validated integer (never user text), so it is formatted in.
SCHEDULE_VQL = (
    "SELECT collect_client(client_id=DfirClientId, artifacts=DfirArtifact, "
    "spec=parse_json(data=DfirSpec){limits}) AS flow FROM scope()"
)
PARAMS_VQL = "SELECT parameters FROM artifact_definitions(names=DfirName)"

# Artifact parameter names that take the start / end of a time window.
TIME_AFTER_PARAMS = {"dateafter", "startdate", "starttime", "earliesttime", "timeafter", "fromdate", "datetimeafter"}
TIME_BEFORE_PARAMS = {"datebefore", "enddate", "endtime", "latesttime", "timebefore", "todate", "datetimebefore"}

POLL_VQL = (
    "SELECT state, status, total_collected_rows, artifacts_with_results "
    "FROM flows(client_id=DfirClientId, flow_id=DfirFlowId)"
)
SOURCE_VQL = "SELECT * FROM source(client_id=DfirClientId, flow_id=DfirFlowId, artifact=DfirArtifact)"
# Named sources ("Artifact/Source") are addressed with a separate `source` argument.
SOURCE_NAMED_VQL = ("SELECT * FROM source(client_id=DfirClientId, flow_id=DfirFlowId, "
                    "artifact=DfirArtifact, source=DfirSource)")
HOSTNAME_VQL = "SELECT os_info.hostname AS hostname FROM clients(client_id=DfirClientId)"
FLOW_LOGS_VQL = "SELECT * FROM flow_logs(client_id=DfirClientId, flow_id=DfirFlowId)"

# Flow log lines worth showing when a collection is empty or failed.
_LOG_PROBLEM = re.compile(r"(?i)(warn|error|denied|fail|not found|cannot|unable|no such|invalid|disabled)")
MAX_LOG_LINES = 15
# "Call to plugin wmi disabled": the dead-disk remapping disables live-only plugins.
_DISABLED_RE = re.compile(r"(?i)(?:plugin|function)\s+(\w+)\s+disabled")

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
    from copilot.knowledge import artifact_info
    info = artifact_info(artifact)
    if info.get("learned_unusable"):
        raise CollectionError(f"'{artifact}' does not work on disk images (lesson learned on this server: "
                              f"{info['learned_unusable']}). Use another source.")
    if info.get("live_only"):
        raise CollectionError(
            f"'{artifact}' only works on a running system and returns nothing from a disk image. "
            f"{info.get('meaning', '')}".strip())
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


def parameter_specs(artifact: str, vql) -> list:
    """The artifact's declared parameters as dicts ([] if they can't be looked up)."""
    try:
        rows, _ = _run(vql, PARAMS_VQL, {"DfirName": artifact})
    except CollectionError:
        return []
    return [p for p in ((rows[0].get("parameters") if rows else None) or []) if p.get("name")]


def artifact_parameters(artifact: str, vql) -> list:
    """Parameter names the artifact accepts ([] if they can't be looked up)."""
    return [p["name"] for p in parameter_specs(artifact, vql)]


def _shorten(text, limit: int = 90) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def check_parameter_names(artifact: str, params: dict, specs: list) -> dict:
    """
    Velociraptor ignores parameters an artifact doesn't declare and runs with its defaults,
    so a guessed name looks like "nothing found". Agent requests must use declared names
    (a different letter case is corrected). Skipped when the declaration can't be looked up.
    """
    if not specs or not params:
        return dict(params or {})
    declared = {p["name"].lower(): p["name"] for p in specs}
    unknown = [k for k in params if k.lower() not in declared]
    if unknown:
        accepted = "; ".join(
            p["name"] + (f" (default {_shorten(p['default'], 60)!r})" if p.get("default") not in (None, "") else "")
            + (f": {_shorten(p['description'])}" if p.get("description") else "")
            for p in specs[:30])
        raise CollectionError(
            f"'{artifact}' has no parameter {', '.join(map(repr, unknown))}. Velociraptor would ignore "
            f"it and run with the defaults, so an empty result would mean nothing. Accepted parameters: "
            f"{accepted}. Retry with these names (describe_artifact shows the full description).")
    return {declared[k.lower()]: v for k, v in params.items()}


def csv_parameters(params: dict, specs: list) -> dict:
    """
    Parameters of type csv are CSV text with a header line (e.g. "Path\\nC:/Users/*/Downloads/**").
    A list (of values or of dicts) or a bare value without the header becomes that text, with the
    header taken from the parameter's default; otherwise Velociraptor would read it as a table
    with the wrong column and match nothing.
    """
    params = dict(params or {})
    for spec in specs or []:
        name = spec.get("name")
        if spec.get("type") != "csv" or name not in params or params[name] in (None, ""):
            continue
        value = params[name]
        header = (str(spec.get("default") or "").strip().splitlines() or [""])[0].strip()
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            columns = list(dict.fromkeys(k for v in value for k in v))
            writer.writerow(columns)
            writer.writerows([[v.get(c, "") for c in columns] for v in value])
        elif isinstance(value, list) and header:
            writer.writerow([header])
            writer.writerows([[v] for v in value])
        elif isinstance(value, str) and header and "," not in header and value.splitlines()[0].strip() != header:
            writer.writerow([header])
            writer.writerows([[line.strip()] for line in value.splitlines() if line.strip()])
        else:
            continue
        params[name] = out.getvalue()
    return params


def with_time_window(artifact: str, params: dict, vql, specs: list = None) -> tuple:
    """
    Fills the artifact's own date-filter parameters from the case scope, so
    Velociraptor drops out-of-window rows before sending them. Parameters the
    caller set explicitly are left alone. Returns (params, names_applied).
    """
    params = dict(params or {})
    if not (case_config.apply_time_window and case_config.has_scope):
        return params, []
    given = {k.lower() for k in params}
    applied = []
    names = [p["name"] for p in specs] if specs is not None else artifact_parameters(artifact, vql)
    for name in names:
        low = name.lower()
        if low in given:
            continue
        if low in TIME_AFTER_PARAMS:
            params[name] = case_config.start_time
            applied.append(name)
        elif low in TIME_BEFORE_PARAMS:
            params[name] = case_config.end_time
            applied.append(name)
    return params, applied


def _schedule_query(with_limits: bool) -> str:
    limits = f", max_rows={int(case_config.max_rows)}" if with_limits else ""
    return SCHEDULE_VQL.format(limits=limits)


def schedule(artifact: str, params: dict = None, vql=None) -> str:
    """Starts a collection on the case client and returns its flow ID."""
    vql = vql or get_vql()
    client_id = _target_client()
    _check_artifact(artifact)
    encoded = encode_params(params)

    env = {"DfirClientId": client_id, "DfirArtifact": artifact, "DfirSpec": json.dumps({artifact: encoded})}
    query = _schedule_query(with_limits=True)
    rows, log = _run(vql, query, env)
    if not rows and "max_rows" in log:
        # Older collect_client without row limits: our ingest cap still applies.
        query = _schedule_query(with_limits=False)
        rows, log = _run(vql, query, env)
    case_db.log_query("collect_artifact", f"{query} -- env={json.dumps(env)}", len(rows), artifact)

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
    truncated = False
    limit = case_config.max_rows
    for sub_artifact in sub_artifacts:
        if read >= limit:
            truncated = True
            break
        query, env = _source_query(client_id, flow_id, sub_artifact)
        logs = []
        counted = [0]
        budget = limit - read

        def counting(rows):
            nonlocal truncated
            for row in rows:
                if counted[0] >= budget:
                    truncated = True
                    return
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
    return {"rows_read": read, "new_rows": new, "truncated": truncated}


def flow_log_problems(client_id: str, flow_id: str, vql) -> list:
    """Warning/error lines from the flow's own log on the Velociraptor side ([] if unavailable)."""
    try:
        rows, _ = _run(vql, FLOW_LOGS_VQL, {"DfirClientId": client_id, "DfirFlowId": flow_id})
    except CollectionError:
        return []
    lines = []
    for row in rows:
        level = str(row.get("level") or row.get("Level") or "")
        message = str(row.get("message") or row.get("Message") or "")
        if _LOG_PROBLEM.search(f"{level} {message}"):
            lines.append(f"{level}: {message}".strip(": ")[:500])
    return lines[-MAX_LOG_LINES:]


def _finish(flow_id: str, status: dict, vql) -> dict:
    """Ingests if finished, and attaches Velociraptor's log when the result needs explaining."""
    result = ingest(flow_id, status, vql) if status["state"] == "FINISHED" else None
    summary = _summary(flow_id, status, result)
    empty = status["state"] == "FINISHED" and not status["total_collected_rows"]
    if empty or status["state"] in ("ERROR", "CANCELLED"):
        problems = flow_log_problems(case_db.get_collection(flow_id)["client_id"], flow_id, vql)
        if problems:
            summary["velociraptor_log"] = problems
            disabled = sorted({m.group(1) for line in problems for m in _DISABLED_RE.finditer(line)})
            # Some artifacts call a live-only function only for a detail (e.g. Prefetch: winobj to show
            # drive letters) and work without it: the knowledge base lists those as harmless.
            from copilot.knowledge import artifact_info
            harmless = {h.lower() for h in artifact_info(summary.get("artifact") or "").get("harmless_disabled") or []}
            disabled = [d for d in disabled if d.lower() not in harmless]
            if disabled:
                summary["note"] = (
                    f"This artifact relies on {', '.join(disabled)}, which only works on a running system "
                    f"and is disabled for disk images. It cannot produce results here; use an artifact "
                    f"based on files, registry or event logs instead.")
    return summary


def _empty_note(flow_id: str, known: dict) -> str:
    """Why a collection may have returned nothing, judged from what this case collected before."""
    others = [c for c in case_db.get_collections()
              if c["flow_id"] != flow_id and c.get("client_id") == known.get("client_id")
              and (c.get("rows_ingested") or 0) > 0]
    params = known.get("parameters") or "{}"
    if any(c["artifact"] == known.get("artifact") for c in others):
        return (f"Velociraptor collected 0 rows. This artifact works on this image (an earlier collection of it "
                f"returned rows), so nothing matched these parameters {params}: the filter may be too narrow, "
                f"the time window may exclude it, or the data is gone (e.g. a deleted file whose record was "
                f"reused). Do not blame the disk mapping.")
    if others:
        return (f"Velociraptor collected 0 rows. The image is readable (other collections from it returned "
                f"rows), so most likely nothing matched these parameters {params}, or the data is not on "
                f"this image.")
    return ("Velociraptor collected 0 rows. The artifact found nothing on the image; on a dead disk this can "
            "also mean its paths did not resolve through the remapping (no collection from this image has "
            "returned rows yet).")


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
            summary["note"] = _empty_note(flow_id, known)
        elif not result.get("rows_read"):
            summary["note"] = ("Velociraptor reports rows but none could be read back, so nothing was "
                               "ingested. This is a copilot problem, not an empty result; check_collection "
                               "will retry.")
            if known.get("error"):
                summary["read_log"] = known["error"]
        elif not result.get("new_rows"):
            summary["note"] = "All rows were already in the case database (collected before)."
        if result.get("truncated") or (total and total >= case_config.max_rows):
            summary["truncated"] = True
            summary["note"] = (f"Hit the {case_config.max_rows:,}-row limit: results are INCOMPLETE. "
                               f"Collect again with narrower filters rather than drawing conclusions "
                               f"from what is missing.")
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
    return _finish(flow_id, poll(flow_id, vql), vql)


# Filter values that match everything are not filters (e.g. FileRegex ".").
_MATCH_ALL = {".", ".*", ".+", "^.*$", "^.*", ".*$", "*", "(?i).", "(?i).*", "^", "$", "^.+$"}


# A time window this short is a real filter, even on heavy artifacts (e.g. the USN journal
# for the minutes around an event, to see every file touched then).
NARROW_WINDOW_MINUTES = 60


def _window_minutes(params: dict):
    """Length of the window given in the parameters, in minutes (None if not both ends)."""
    from copilot.normalize import parse_timestamp
    after = next((v for k, v in (params or {}).items() if k.lower() in TIME_AFTER_PARAMS and v), None)
    before = next((v for k, v in (params or {}).items() if k.lower() in TIME_BEFORE_PARAMS and v), None)
    start, end = parse_timestamp(str(after or ""), "time"), parse_timestamp(str(before or ""), "time")
    if not (start and end):
        return None
    return (end - start).total_seconds() / 60


def check_agent_request(artifact: str, params: dict):
    """Rules for collections the agent asks for (before the investigator is asked)."""
    if case_config.is_heavy(artifact):
        filters = [k for k, v in (params or {}).items()
                   if v not in (None, "") and str(v).strip() not in _MATCH_ALL
                   and k.lower() not in TIME_AFTER_PARAMS | TIME_BEFORE_PARAMS]
        minutes = _window_minutes(params)
        if not filters and not (minutes is not None and 0 <= minutes <= NARROW_WINDOW_MINUTES):
            raise CollectionError(
                f"'{artifact}' can return millions of rows. Pass at least one real filter parameter "
                f"(e.g. a filename/path regex, event IDs or a search regex; see describe_artifact) "
                f"based on a lead you already have, or a time window of at most {NARROW_WINDOW_MINUTES} "
                f"minutes around an event. Patterns that match everything don't count.")


def collect(artifact: str, params: dict = None, wait_seconds: int = None, vql=None,
            sleep=time.sleep, requested_by: str = "investigator") -> dict:
    """
    Schedules a collection and waits up to `wait_seconds` for it to finish.
    `requested_by="agent"` applies the agent rules (filters for heavy artifacts,
    investigator approval).
    """
    vql = vql or get_vql()
    _target_client()
    _check_artifact(artifact)
    specs = parameter_specs(artifact, vql)
    if requested_by == "agent":
        params = check_parameter_names(artifact, params, specs)
    params = csv_parameters(params, specs)
    params, window = with_time_window(artifact, params, vql, specs)
    if requested_by == "agent":
        # The investigator approves (or the case allows) agent collections before anything runs.
        # Requests approved later (Streamlit) are run by approvals.execute as the investigator's.
        from copilot import approvals
        check_agent_request(artifact, params)
        try:
            approvals.gate("collect", f"{artifact} {json.dumps(params)}" if params else artifact,
                           {"artifact": artifact, "params": params})
        except approvals.ApprovalError as e:
            raise CollectionError(str(e))
    wait = case_config.collection_wait_seconds if wait_seconds is None else wait_seconds
    flow_id = schedule(artifact, params, vql)

    deadline = time.monotonic() + wait
    while True:
        status = poll(flow_id, vql)
        if status["state"] in TERMINAL_STATES or time.monotonic() >= deadline:
            break
        sleep(POLL_INTERVAL)

    summary = _finish(flow_id, status, vql)
    if window:
        summary["time_window_applied"] = {name: params[name] for name in window}
    return summary
