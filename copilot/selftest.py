"""
Checks the Velociraptor setup end to end without the LLM:
    python -m copilot.selftest
"""
import json
import sys

from copilot import collection
from copilot.case_config import case_config
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


def main():
    if case_config.client_id_error:
        print(f"[!] {case_config.client_id_error}")
        sys.exit(1)

    info = _step("API connection", lambda: _query("SELECT * FROM info()"))
    print(f"    server: Velociraptor {info[0].get('Version', {}).get('version', '?')}"
          if isinstance(info[0].get("Version"), dict) else f"    server: {info[0].get('Hostname', '?')}")

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
