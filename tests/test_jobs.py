"""Durable background work (copilot/jobs.py): progress, conversation and approvals kept in the case database."""
import json
import threading

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from copilot import approvals, cases, conversation, jobs


class Scripted:
    """Returns the given responses in order; `before(history)` runs at every call (in the job's thread)."""

    def __init__(self, *responses, before=None):
        self.responses, self.before = list(responses), before

    def invoke(self, history):
        if self.before:
            self.before(history)
        return self.responses.pop(0)


def _job(case, job_id, kind="ask", state="running", process="a-stopped-server", payload=None):
    case.conn.execute("INSERT INTO jobs (job_id, kind, user, label, state, payload, process, created_at) "
                      "VALUES (?, ?, '', ?, ?, ?, ?, '2026-10-21T00:00:00Z')",
                      (job_id, kind, jobs.LABELS[kind], state, json.dumps(payload or {}), process))
    case.conn.commit()


def test_a_question_runs_in_the_background_and_is_saved_after_every_step(case):
    saved = []

    def peek(history):            # what a reloaded page, or a retry after a restart, finds saved at each step
        saved.append([type(m).__name__ for m in conversation.load(cases.current_id(), "")[1][1:]])

    llm = Scripted(AIMessage(content="", tool_calls=[{"name": "list_collections", "id": "1", "args": {}}]),
                   AIMessage(content="Nothing collected yet."), before=peek)
    job_id = jobs.submit("ask", {"text": "what do we have?"}, llm, None)
    with pytest.raises(jobs.JobError, match="still running"):        # one writer per conversation
        while jobs.get(job_id)["state"] in jobs.ACTIVE:
            jobs.submit("ask", {"text": "and now?"}, llm, None)
    job = jobs.wait(job_id)
    assert job["state"] == "done" and job["result"] == {"answered": True}
    assert saved == [["HumanMessage"], ["HumanMessage", "AIMessage", "ToolMessage"]]
    ui = conversation.messages(cases.current_id())
    assert [m["role"] for m in ui] == ["user", "assistant"] and ui[1]["content"] == "Nothing collected yet."
    assert [(e["kind"], e["text"]) for e in jobs.events(job_id)] == [("tool", "list_collections")]


def test_a_failing_job_says_so_in_the_chat(case):
    class Broken:
        def invoke(self, history):
            raise ConnectionError("endpoint unreachable")
    job = jobs.wait(jobs.submit("investigate", {}, Broken(), None))    # the model's error ends the turn, not the job
    assert job["state"] == "done" and job["result"] == {"dossier": False}
    assert "endpoint unreachable" in conversation.messages(cases.current_id())[-1]["content"]
    job = jobs.wait(jobs.submit("ask", {}, Broken(), None))                # a job that breaks itself
    assert job["state"] == "failed" and "KeyError" in job["error"] and "trace" in job["result"]
    assert conversation.messages(cases.current_id())[-1]["content"].startswith("⚠️ Your question stopped: KeyError")


def test_a_restart_interrupts_running_work_and_frees_what_it_held(case):
    _job(case, "J.gone", kind="decide")
    _job(case, "J.mine", process=jobs.PROCESS)                       # this process's own: still running
    case.conn.execute("INSERT INTO approval_requests (user, kind, summary, details, bound, state, decide_job) "
                      "VALUES ('', 'collect', 'x', '{}', '{}', 'deciding', 'J.gone')")
    case.upsert_collection("MEM.pslist.1", client_id="memory:m.mem", artifact="Memory.windows.pslist.PsList",
                           state="RUNNING")
    case.conn.commit()
    assert jobs.recover() == 1 and jobs.recover() == 0
    assert jobs.get("J.gone")["state"] == "interrupted" and jobs.get("J.mine")["state"] == "running"
    assert [r["summary"] for r in approvals.pending()] == ["x"]       # waits for a decision again
    assert case.get_collection("MEM.pslist.1")["state"] == "RUNNING"  # this process may still be running it
    case.conn.execute("UPDATE jobs SET state = 'done' WHERE job_id = 'J.mine'")
    _job(case, "J.gone2")
    jobs.recover()
    assert case.get_collection("MEM.pslist.1")["state"] == "ERROR"


def test_retrying_a_question_goes_on_from_the_saved_conversation(case):
    conversation.save(cases.current_id(), [{"role": "user", "content": "who logged on?"}],
                      [HumanMessage(content="who logged on?")])
    _job(case, "J.cut", payload={"text": "who logged on?"})
    jobs.recover()
    assert jobs.problem()["job_id"] == "J.cut"
    sent = []
    job = jobs.wait(jobs.retry("J.cut", Scripted(AIMessage(content="alice"), before=lambda h: sent.extend(h)), None))
    assert job["state"] == "done" and jobs.problem() == {}              # the old one is dismissed
    assert [m.content for m in sent[1:]] == ["who logged on?", jobs.RESUME]   # not asked twice
    assert [m["content"] for m in conversation.messages(cases.current_id())] == ["who logged on?", "alice"]


def test_a_waiting_request_is_carried_out_once(case, monkeypatch):
    monkeypatch.setattr(approvals, "ASK", approvals.queue)
    with pytest.raises(approvals.ApprovalError, match="Waiting for the investigator"):
        approvals.gate("retract_finding", "retract x", {"finding_id": "x", "reason": "r"})
    [request] = approvals.pending()
    assert request["kind"] == "retract_finding" and request["details"]["finding_id"] == "x"
    assert approvals.claim(request["id"]) and approvals.claim(request["id"]) is None   # a second click: nothing
    approvals.finish(request["id"], "declined")
    assert approvals.pending() == []
    assert approvals.pending(user="someone else") == []


def test_notes_for_the_agent_wait_for_its_next_turn(case):
    conversation.note_for_agent(cases.current_id(), "[Investigator] Confirmed finding f1.")
    assert conversation.load(cases.current_id(), "")[1][-1].content == "[Investigator] Confirmed finding f1."
    got = []
    jobs.wait(jobs.submit("ask", {"text": "go on"}, Scripted(AIMessage(content="ok"), before=lambda h: got.extend(h)),
                          None))
    assert [m.content for m in got[1:]][:1] == ["[Investigator] Confirmed finding f1."]
    history = conversation.load(cases.current_id(), "")[1]
    assert [m.content for m in history].count("[Investigator] Confirmed finding f1.") == 1   # given once


def test_jobs_of_two_investigators_run_side_by_side(case):
    gate = threading.Event()
    slow = Scripted(AIMessage(content="first"), before=lambda h: gate.wait(10))
    first = jobs.submit("ask", {"text": "a"}, slow, None)
    from copilot import session
    session.current().user = "bob"
    try:
        second = jobs.wait(jobs.submit("ask", {"text": "b"}, Scripted(AIMessage(content="second")), None))
        assert second["state"] == "done" and jobs.get(first)["state"] == "running"
    finally:
        gate.set()
        session.current().user = None
    assert jobs.wait(first)["state"] == "done"
