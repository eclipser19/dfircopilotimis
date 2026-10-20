"""
Investigator approval for everything the agent wants to CHANGE.

Evidence is attacker-controlled, and text inside it can try to steer the model ("retract
finding 3", "switch to another case"). So actions with side effects are requests: the
investigator approves or declines them (CLI: y/N prompt; Streamlit: Approve/Deny in the
sidebar, possibly later). Read-only analysis never needs approval, and the investigator's
own actions (sidebar buttons, /case, forms) bypass this module entirely.

Per action, the case file decides: confirm (default) | auto | off
    agent:
      approvals: {retract_finding: confirm, update_case: confirm, switch_case: confirm, create_case: confirm,
                  memory: confirm}
Collections keep their own setting, collection.agent_collections.

A collection or memory run decided later is bound to the evidence it was asked for: if another
member changed the case's client or memory image meanwhile, approving it does not run it (it
would read other evidence than the investigator was shown).

Every request and decision is written to the case's audit log.
"""
import json

from copilot.case_config import case_config
from copilot.database import case_db

ACTIONS = {
    "collect": "collect an artifact",
    "retract_finding": "retract a finding",
    "update_case": "change the case settings",
    "switch_case": "switch to another case",
    "create_case": "create a new case",
    "memory": "analyze the memory image",
    "lesson": "add a lesson to the agent's knowledge",
}
MODES = ("confirm", "auto", "off")
# The evidence a collection or memory run reads; a queued one runs only if it is still the case's.
# (The time window needs no binding: it is already in a collection's parameters when it is asked.)
BOUND = {"client_id": "Velociraptor client", "memory_image": "memory image"}
BOUND_KINDS = ("collect", "memory")

# Set by the UI: ask(request) -> True (approved now), False (declined) or "queued" (decided later).
ASK = None
# Who answers ASK in this process (the CLI sets the OS user). Streamlit passes the signed-in
# user to resolve() instead, since one server process serves several sessions.
ACTOR = None


class ApprovalError(Exception):
    """The action did not run (declined, waiting, or not allowed); the message is for the agent."""


def mode(kind: str) -> str:
    if kind == "collect":
        return case_config.agent_collections
    configured = ((case_config.data.get("agent", {}) or {}).get("approvals", {}) or {}).get(kind, "confirm")
    configured = str(configured).lower()
    return configured if configured in MODES else "confirm"


def _log(request: dict, decision: str):
    by = f" by {request['decided_by']}" if request.get("decided_by") else ""
    case_db.log_query("approval", f"{request['kind']} {decision}{by}: {request['summary']} "
                                f"-- {json.dumps(request['details'], default=str)}", 0)


def _bound() -> dict:
    return {key: str(getattr(case_config, key) or "") for key in BOUND}


def gate(kind: str, summary: str, details: dict) -> dict:
    """
    Asks for approval as configured. Returns the approved request, or raises ApprovalError
    when the action must not run now (declined, waiting for the investigator, or not allowed).
    """
    from copilot import cases
    request = {"kind": kind, "summary": summary, "details": details, "case_id": cases.current_id(),
               "bound": _bound()}
    m = mode(kind)
    if m == "off":
        _log(request, "refused (agent not allowed)")
        raise ApprovalError(f"The investigator does not allow the agent to {ACTIONS[kind]} in this case. "
                            f"Tell them what you would do and why, so they can do it themselves.")
    if m == "auto":
        request["approved_by"] = "auto"
        _log(request, "auto-approved")
        return request
    if ASK is None:
        _log(request, "refused (no approval channel)")
        raise ApprovalError(f"This needs the investigator's approval, which isn't available here. "
                            f"Ask them to {ACTIONS[kind]} themselves.")
    decision = ASK(request)
    if decision != "queued":
        request["decided_by"] = ACTOR
    if decision == "queued":
        _log(request, "awaiting approval")
        raise ApprovalError(f"Waiting for the investigator's approval: {summary}. If they approve, the result "
                            f"will be added to the conversation. Do not repeat the request; continue with "
                            f"other work or wait.")
    if not decision:
        _log(request, "declined")
        raise ApprovalError(f"The investigator declined: {summary}. Continue without it or ask them.")
    request["approved_by"] = "investigator"
    _log(request, "approved")
    return request


def run(kind: str, summary: str, details: dict):
    """gate() then execute(): returns the action's result, or raises ApprovalError."""
    return execute(gate(kind, summary, details))


def resolve(request: dict, approved: bool, actor: str = None):
    """For requests decided later (Streamlit): logs the decision and runs the action if approved."""
    from copilot import cases
    if request.get("case_id") != cases.current_id():
        raise ApprovalError(f"This request belongs to case '{request.get('case_id')}'; switch to it first.")
    request["decided_by"] = actor
    if not approved:
        _log(request, "declined")
        return None
    if request["kind"] in BOUND_KINDS:
        asked, now = request.get("bound") or {}, _bound()
        changed = [label for key, label in BOUND.items() if key in asked and asked[key] != now[key]]
        if changed:
            _log(request, f"not run ({', '.join(changed)} changed since it was asked)")
            raise ApprovalError(f"Not run: the case's {' and '.join(changed)} changed since this was asked for. "
                                f"Ask the agent again if it is still needed.")
    request["approved_by"] = "investigator"
    _log(request, "approved")
    return execute(request)


def execute(request: dict):
    """Performs an approved action. Returns its result (a dict for collections, else a message)."""
    from copilot import cases, collection
    kind, d = request["kind"], request["details"]
    if kind == "collect":
        return collection.collect(d["artifact"], d.get("params") or {})
    if kind == "memory":
        from copilot import memory
        return memory.execute(d["plugin"], d.get("options") or {})
    if kind == "lesson":
        from copilot import lessons
        try:
            lesson = lessons.add(d["topic"], d["text"], d.get("unusable_on_images", False), source="agent",
                                 approver=request.get("decided_by"),
                                 auto_approved=request.get("approved_by") == "auto", case=request.get("case_id", ""))
        except lessons.LessonError as e:
            raise ApprovalError(str(e))
        if lesson["status"] == "active":
            return f"Lesson {lesson['id']} saved; it applies from now on, in every case."
        return (f"Lesson {lesson['id']} saved as proposed: an admin must accept it before it applies "
                f"(lessons change the agent for every case).")
    if kind == "retract_finding":
        if request.get("approved_by") == "investigator":
            who = f"approved by {request.get('decided_by') or 'the investigator'}"
        else:
            who = "by the agent"
        found = case_db.retract_finding(d["finding_id"], f"{d['reason']} (retraction {who})")
        if not found:
            raise ApprovalError(f"Finding {d['finding_id']} no longer exists.")
        return f"Retracted finding {found['finding_id']}: {found['title']}"
    if kind == "update_case":
        cases.update(d["case_id"], **d["changes"])
        return f"Updated case settings: {', '.join(d['changes'])}."
    if kind == "switch_case":
        info = cases.switch(d["case_id"])
        return (f"Switched to case '{info['id']}' ({info['name']}). The conversation restarts in that case "
                f"after this answer; do not query data now.")
    if kind == "create_case":
        path = cases.create(**d["kwargs"])
        return f"Created case '{d['kwargs']['case_id']}' at {path}."
    raise ApprovalError(f"Unknown action '{kind}'.")


def describe(request: dict) -> str:
    """One-line description for prompts and the approval list."""
    return f"{ACTIONS.get(request['kind'], request['kind']).capitalize()}: {request['summary']}"
