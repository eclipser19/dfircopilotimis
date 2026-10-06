import sys

try:
    from copilot.agent import run_agent_loop
except Exception as e:  # e.g. SchemaError: case.db from an older version
    if e.__class__.__name__ != "SchemaError":
        raise
    sys.exit(f"[!] {e}")

if __name__ == "__main__":
    run_agent_loop()
