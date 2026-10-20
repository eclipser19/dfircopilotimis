"""
Checks the Velociraptor setup end to end without the LLM:
    python -m copilot.selftest
Inspects one flow (what Velociraptor holds vs. what can be read back):
    python -m copilot.selftest --flow F.XXXX
"""
import json
import sys

from copilot import collection
from copilot.case_config import case_config
from copilot.database import case_db
from copilot.vql_client import get_vql


def _step(name, fn):
    print(f"[*] {name} ... ", end="", flush=True)
    try:
        result = fn()
        print("ok")
        return result
    except Exception as e:  # report and stop on the first failure
        print(f"FAILED\n    {e}")
        sys.exit(1)


def _query(vql_text, env=None):
    res = get_vql().run_vql(vql_text, env=env)
    if res.get("error"):
        raise RuntimeError(f"{res['error']}\n{collection._clean_log(res.get('log', ''))}")
    if not res.get("results"):
        raise RuntimeError(f"no rows returned\n{collection._clean_log(res.get('log', ''))}")
    return res["results"]


def inspect_flow(flow_id: str):
    env = {"DfirClientId": case_config.client_id, "DfirFlowId": flow_id}
    res = get_vql().run_vql(collection.POLL_VQL, env=env)
    print(f"flows(): {json.dumps(res.get('results'), indent=2, default=str)}")
    if res.get("error") or collection._clean_log(res.get("log", "")):
        print(f"  error/log: {res.get('error') or ''} {collection._clean_log(res.get('log', ''))}")
    if not res.get("results"):
        return

    logs = get_vql().run_vql(collection.FLOW_LOGS_VQL, env=env)
    print("\nflow log:")
    for row in logs.get("results", [])[-40:]:
        print(f"  {row.get('level', '')}: {row.get('message', '')}")
    if logs.get("error"):
        print(f"  (could not read flow log: {logs['error']})")

    flow = res["results"][0]
    names = list(flow.get("artifacts_with_results") or [])
    artifact = case_db.get_collection(flow_id).get("artifact")
    if artifact and artifact not in names:
        names.append(artifact)

    for name in names:
        query, qenv = collection._source_query(case_config.client_id, flow_id, name)
        variants = [(query, qenv)]
        if "/" in name:  # also try the combined "Artifact/Source" form
            variants.append((collection.SOURCE_VQL, {**env, "DfirArtifact": name}))
        for q, e in variants:
            r = get_vql().run_vql(q, env=e)
            rows = r.get("results", [])
            print(f"\nsource {json.dumps({k: v for k, v in e.items() if k != 'DfirClientId'})}: {len(rows)} rows")
            log = collection._clean_log(r.get("log", ""))
            if r.get("error") or log:
                print(f"  error/log: {r.get('error') or ''} {log}")
            if rows:
                print(f"  first row: {json.dumps(rows[0], default=str)[:1500]}")


def main():
    from copilot import config_check
    for problem in config_check.server_problems():
        print(f"[!] server settings: {problem}")
    for problem in config_check.case_problems(case_config):
        print(f"[!] case settings ({case_config.path}): {problem}")
    if case_config.client_id_error:
        print(f"[!] {case_config.client_id_error}")
        sys.exit(1)

    if len(sys.argv) == 3 and sys.argv[1] == "--flow":
        inspect_flow(sys.argv[2])
        return

    # Needs no special permission (info() would need MACHINE_STATE, which an
    # investigator-role API user rightly doesn't have).
    _step("API connection", lambda: _query("SELECT 1 AS ok FROM scope()"))

    client = _step(f"client {case_config.client_id}", lambda: _query(
        "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os FROM clients(client_id=DfirClientId)",
        {"DfirClientId": case_config.client_id}))
    print(f"    {json.dumps(client[0])}")

    _step("artifact definitions", lambda: _query(
        "SELECT name FROM artifact_definitions(names=DfirName)", {"DfirName": "Generic.Client.Info"}))

    summary = _step("collect Generic.Client.Info", lambda: collection.collect("Generic.Client.Info", wait_seconds=60))
    print(f"    {json.dumps(summary)}")
    if summary.get("state") != "FINISHED":
        print("[!] The collection did not finish. Is the dead-disk client process running?")
        sys.exit(1)
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
