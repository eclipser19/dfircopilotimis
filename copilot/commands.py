"""
Chat commands handled locally, without the LLM (they cost no tokens):
  /cases          list investigations
  /case <id>      switch to another investigation (the conversation restarts)
  /help           this list
/investigate (uses the LLM) is run by the CLI loop and the app themselves.
"""
from copilot import cases

INVESTIGATE = "/investigate"
HELP = ("Commands (no LLM, free): `/cases` list cases · `/case <id>` switch case (each case keeps its own "
        "chat) · `/help`. CLI: `/new` starts a fresh conversation (Streamlit: sidebar button). "
        "`/investigate` (uses the LLM) investigates the whole case and writes the case dossier every question "
        "starts from. "
        "You can also just ask in words, e.g. \"switch to the szechuan case\" or \"create a case for host X\".")


def handle(text: str):
    """Returns the reply for a command, or None if the text is not a command."""
    stripped = (text or "").strip()
    if not stripped.startswith("/"):
        return None
    parts = stripped.split(maxsplit=1)
    command, arg = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")
    if command == "/cases":
        rows = cases.list_cases()
        if not rows:
            return "No cases found. Create one under `cases/<id>/case.yaml`, or ask me to create one."
        lines = [f"{'▶' if c['active'] else ' '} `{c['id']}` — {c['name']}"
                 f"{'' if c['has_data'] else ' (no data yet)'}" for c in rows]
        return "Cases:\n\n" + "\n".join(f"- {line}" for line in lines) + "\n\nSwitch with `/case <id>`."
    if command == "/case":
        if not arg:
            return f"Active case: `{cases.current_id()}`. Switch with `/case <id>`; list with `/cases`."
        try:
            info = cases.switch(arg)
        except cases.CaseError as e:
            return str(e)
        return f"Switched to case `{info['id']}` — {info['name']}. Starting a fresh conversation for this case."
    if command == "/help":
        return HELP
    return f"Unknown command `{command}`. {HELP}"
