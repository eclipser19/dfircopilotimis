"""
Durable work for the web app.

A question, the investigation, the triage and the approvals an investigator decided each run as a
job: the page submits it and follows its progress, and the work runs in a thread of the server
process on a fork of the investigator's session (session.Session.fork). A refresh, a closed tab or
a second page of the same user loses nothing: the job, its progress (job_events), the requests
waiting for approval and the conversation (saved after every agent step) are in the case database.

After a server restart the jobs that were running are interrupted (recover()). Retrying one goes on
from the saved conversation, and the collections it had started are reused, not scheduled again
(collection.collect), so a retry repeats no side effect; a request it was carrying out waits for a
decision again.

One job at a time per investigator and case: their conversation has one writer.
"""
import json
import re
import sqlite3
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage

from copilot import session
from copilot.case_config import case_config
from copilot.database import case_db

PROCESS = uuid.uuid4().hex[:12]     # this server process: jobs another one was running are interrupted
WORKERS = 4                         # jobs running at once in the process, all cases and users together
ACTIVE = ("queued", "running")
LABELS = {"ask": "Investigating...",
          "investigate": "Investigating the whole case: one longer turn that writes the case dossier...",
          "triage": "Running the triage...",
          "decide": "Carrying out your decisions..."}
NAMES = {"ask": "Your question", "investigate": "The investigation", "triage": "The triage", "decide": "Your approvals"}
CONTINUE = ("[Investigator] Every pending request has been decided (see the results above). Continue the "
            "investigation with them and answer the open question.")
RESUME = ("[Copilot] Your previous turn was cut short (the server restarted). Continue it from where it stopped; "
          "do not repeat steps whose results are above.")

_pool = None
_lock = threading.Lock()
_thread = threading.local()


class JobError(Exception):
    """The job was not started; the message is for the investigator."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def current_job_id() -> str:
    """The job this thread is running (None outside a job)."""
    return getattr(_thread, "job_id", None)


def _executor() -> ThreadPoolExecutor:
    global _pool
    with _lock:
        if _pool is None:
            _pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="dfir-job")
        return _pool


def _row(row) -> dict:
    job = dict(row)
    for key in ("payload", "result"):
        job[key] = json.loads(job[key]) if job.get(key) else {}
    return job


def get(job_id: str) -> dict:
    row = case_db.conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    return _row(row) if row else {}


def active(user: str = None) -> dict:
    """The user's queued or running job in the current case ({} if none)."""
    row = case_db.conn.execute("SELECT * FROM jobs WHERE user = ? AND state IN ('queued', 'running') "
                               "ORDER BY created_at DESC LIMIT 1", (user or "",)).fetchone()
    return _row(row) if row else {}


def problem(user: str = None) -> dict:
    """The user's latest job that was interrupted or failed and is not dismissed yet ({} if none)."""
    row = case_db.conn.execute("SELECT * FROM jobs WHERE user = ? AND state IN ('interrupted', 'failed') "
                               "AND seen = 0 ORDER BY created_at DESC LIMIT 1", (user or "",)).fetchone()
    return _row(row) if row else {}


def dismiss(job_id: str):
    case_db.conn.execute("UPDATE jobs SET seen = 1 WHERE job_id = ?", (job_id,))
    case_db.conn.commit()


def events(job_id: str, after: int = 0) -> list:
    """The job's progress, in order, from after `after` (a seq)."""
    return [dict(r) for r in case_db.conn.execute(
        "SELECT seq, kind, text FROM job_events WHERE job_id = ? AND seq > ? ORDER BY seq", (job_id, after))]


def _set(job_id: str, conn=None, **fields):
    conn = conn or case_db.conn
    names = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE jobs SET {names} WHERE job_id = ?", (*fields.values(), job_id))
    conn.commit()


def submit(kind: str, payload: dict = None, llm=None, finalizer=None, usage=None) -> str:
    """
    Starts a job for the current session's user in its case and returns its ID. `llm`, `finalizer` and
    `usage` are the investigator's own objects (their API key); they live in this process only.
    """
    if kind not in HANDLERS:
        raise JobError(f"Unknown job '{kind}'.")
    user = session.current_user() or ""
    with _lock:
        running = active(user)
        if running:
            raise JobError(f"'{running['label']}' is still running: wait for it to finish.")
        job_id = f"J.{datetime.now(timezone.utc):%Y%m%d%H%M%S}.{uuid.uuid4().hex[:6]}"
        case_db.conn.execute("INSERT INTO jobs (job_id, kind, user, label, state, payload, process, created_at) "
                             "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)",
                             (job_id, kind, user, LABELS[kind], json.dumps(payload or {}, default=str), PROCESS, _now()))
        case_db.conn.commit()
    fork = session.current().fork()
    _executor().submit(_run, job_id, kind, dict(payload or {}), fork,
                       {"llm": llm, "finalizer": finalizer, "usage": usage})
    return job_id


def retry(job_id: str, llm=None, finalizer=None, usage=None) -> str:
    """Runs an interrupted or failed job again; a question goes on from where its conversation stopped."""
    job = get(job_id)
    if not job:
        raise JobError(f"No job {job_id}.")
    dismiss(job_id)
    payload = dict(job["payload"], resume=job["kind"] == "ask")
    return submit(job["kind"], payload, llm, finalizer, usage)


def wait(job_id: str, timeout: float = 60, poll: float = 0.05) -> dict:
    """The job once it has ended (or as it is after `timeout` seconds)."""
    deadline = time.monotonic() + timeout
    while True:
        job = get(job_id)
        if job.get("state") not in ACTIVE or time.monotonic() >= deadline:
            return job
        time.sleep(poll)


def recover() -> int:
    """
    Jobs another server process was running are interrupted: their thread is gone. Requests they were
    carrying out wait for a decision again, and memory runs left RUNNING are marked failed (Velociraptor
    collections go on in Velociraptor: a retry picks them up). Returns how many jobs were interrupted.
    """
    ids = [r[0] for r in case_db.conn.execute(
        "SELECT job_id FROM jobs WHERE state IN ('queued', 'running') AND process != ?", (PROCESS,))]
    if not ids:
        return 0
    marks = ",".join("?" * len(ids))
    case_db.conn.execute(f"UPDATE jobs SET state = 'interrupted', finished_at = ?, error = ? WHERE job_id IN ({marks})",
                         (_now(), "The server stopped while this ran.", *ids))
    case_db.conn.execute(f"UPDATE approval_requests SET state = 'pending', decide_job = NULL "
                         f"WHERE state = 'deciding' AND decide_job IN ({marks})", ids)
    if not case_db.conn.execute("SELECT 1 FROM jobs WHERE state IN ('queued', 'running') AND process = ?",
                                (PROCESS,)).fetchone():
        case_db.conn.execute("UPDATE collections SET state = 'ERROR', error = 'Interrupted: the server stopped while "
                             "it ran. Run it again.', finished_at = ? WHERE flow_id LIKE 'MEM.%' AND state = 'RUNNING'",
                             (_now(),))
    case_db.conn.commit()
    return len(ids)


# ---------------------------------------------------------------- running a job
class _Work:
    """
    What a job knows while it runs: its payload, the investigator's model, its progress so far. `book` is a
    connection to the database of the case it started in: its own records stay there even if the agent
    switches the job's session to another case.
    """

    def __init__(self, job_id: str, payload: dict, handles: dict, book):
        from copilot import cases
        self.job_id, self.payload, self.book = job_id, payload, book
        self.llm, self.finalizer, self.usage = handles["llm"], handles["finalizer"], handles["usage"]
        self.case_id, self.user = cases.current_id(), session.current_user()
        self.log, self.notices, self.seq, self.history = [], [], 0, None

    def event(self, kind: str, text: str):
        self.seq += 1
        self.book.execute("INSERT INTO job_events VALUES (?, ?, ?, ?, ?)", (self.job_id, self.seq, _now(), kind, text))
        self.book.commit()

    def emit(self, kind: str, payload):
        """run_turn's progress events: kept as the job's progress and the message's steps."""
        if kind == "tool":
            self.log.append(f"⚙️ {payload}")
            self.event("tool", str(payload))
        elif kind == "collection":
            self.log.append(f"   {payload}")
            self.event("collection", str(payload))
        elif kind == "notice":
            self.notices.append(str(payload))
            self.event("notice", str(payload))
        elif kind == "usage":
            self.log.append(str(payload))
        if kind in ("step", "usage") and self.history is not None:
            self.checkpoint()             # every finished step is saved: a retry goes on from there

    def checkpoint(self):
        from copilot import conversation
        conversation.save_history(self.case_id, self.history, user=self.user)

    def say(self, *messages: dict):
        from copilot import conversation
        conversation.append(self.case_id, *messages, user=self.user)

    def begin(self) -> list:
        """The conversation's agent history, with a fresh system prompt and the investigator's waiting notes."""
        from copilot import conversation
        from copilot.prompts import build_system_prompt
        self.history = conversation.begin(self.case_id, build_system_prompt(case_config), user=self.user)[1]
        return self.history

    def need_model(self):
        if self.llm is None:
            raise JobError("No model: enter the API key in the sidebar first.")

    def outcome(self) -> dict:
        """What the page must do afterwards: follow a case the agent switched to."""
        from copilot import cases
        now = cases.current_id()
        return {"switch_to": now} if now != self.case_id else {}


def _run(job_id: str, kind: str, payload: dict, fork, handles: dict):
    _thread.job_id = job_id
    book = sqlite3.connect(fork.db.db_path, timeout=60, check_same_thread=False)
    book.row_factory = sqlite3.Row
    try:
        with session.use(fork):
            work = None
            try:
                _set(job_id, book, state="running", started_at=_now(), process=PROCESS)
                work = _Work(job_id, payload, handles, book)
                result = HANDLERS[kind](work) or {}
                _set(job_id, book, state="done", finished_at=_now(), result=json.dumps({**result, **work.outcome()}))
            except BaseException as e:          # whatever happens, the job ends with a state the page can show
                detail = f"{type(e).__name__}: {e}" if not isinstance(e, JobError) else str(e)
                _set(job_id, book, state="failed", finished_at=_now(), error=detail[:4000],
                     result=json.dumps({"trace": traceback.format_exc()[-4000:]}))
                if work is not None:
                    try:
                        work.say({"role": "assistant", "content": f"⚠️ {NAMES[kind]} stopped: {detail}"})
                    except Exception:
                        pass
    finally:
        _thread.job_id = None
        book.close()
        fork.close()


def _turn(work: _Work, text: str, show_user: bool, question: str = None) -> dict:
    """One agent turn in the investigator's conversation; the history is saved after every step."""
    from copilot import knowledge, outputs
    from copilot.agent import run_turn
    work.need_model()
    history = work.history if work.history is not None else work.begin()
    if work.payload.get("resume") and any(isinstance(m, HumanMessage) and text in str(m.content) for m in history):
        history.append(HumanMessage(content=RESUME))
    else:
        if show_user:
            work.say({"role": "user", "content": text})
        # Questions typed by the investigator get the matching playbooks attached (automatic prompts don't).
        history.append(HumanMessage(content=knowledge.with_playbooks(text) if show_user else text))
    work.checkpoint()
    before = outputs.last_output_id()
    answer = run_turn(work.llm, history, case_config.max_steps, work.usage, case_config.max_tokens_per_turn,
                      work.finalizer, work.emit)
    work.checkpoint()
    content = answer or "\n\n".join(f"⚠️ {n}" for n in work.notices) or "No answer."
    # Links to local paths can't work in a browser; files come as download buttons instead.
    content = re.sub(r"\[([^\]]+)\]\((?!https?://)[^)]*\)", r"\1", content)
    work.say({"role": "assistant", "content": content, "log": work.log, "files": outputs.produced_since(before),
              "answer": bool(answer), "question": question if question is not None else (text if show_user else "")})
    return {"answered": bool(answer)}


def _ask(work: _Work) -> dict:
    return _turn(work, work.payload["text"], work.payload.get("show_user", True))


def _investigation(work: _Work, extra: str = "") -> dict:
    from copilot import dossier
    work.need_model()
    work.event("status", LABELS["investigate"])
    try:
        entry = dossier.investigate(work.llm, work.finalizer, work.usage, work.emit, extra)
    except dossier.DossierError as e:
        work.say({"role": "assistant", "log": work.log, "content": "\n\n".join(f"⚠️ {n}" for n in [*work.notices, str(e)])})
        return {"dossier": False}
    work.say({"role": "assistant", "log": work.log, "answer": True, "kind": "dossier",
              "question": "Investigate the whole case (the case dossier)",
              "content": f"🗂️ **Case dossier** — every question now starts from it ({entry['steps']} steps, "
                         f"{entry['tokens']:,} tokens)\n\n{entry['text']}"})
    return {"dossier": True}


def _investigate(work: _Work) -> dict:
    if work.payload.get("command"):
        work.say({"role": "user", "content": work.payload["command"]})
    return _investigation(work, work.payload.get("extra", ""))


def _triage(work: _Work) -> dict:
    """The triage, no LLM: the disk collections and the memory plugins; then, if chosen, the investigation."""
    from copilot import collection, dossier, memory
    from copilot.agent import status_line
    p = work.payload
    disk, mem = [], []
    if p.get("disk", True):
        lines = []
        work.event("status", "Running triage collection...")
        for step in p.get("plan") or case_config.collection_plan:
            artifact, params = step["artifact"], step.get("parameters") or {}
            work.event("status", f"Collecting `{artifact}`...")
            try:
                summary = collection.collect(artifact, params)
            except collection.CollectionError as e:
                summary = {"artifact": artifact, "state": "NOT_STARTED", "error": str(e)}
            disk.append(summary)
            lines.append(status_line(summary))
            work.event("collection", lines[-1])
        work.say({"role": "assistant", "content": "**Triage collection**\n\n```\n" + "\n".join(lines) + "\n```"})
    if p.get("plugins"):
        work.event("status", "Running memory triage (each plugin can take minutes)...")
        mem = memory.triage(progress=lambda plugin: work.event("status", f"Running `{plugin}`..."),
                            plugins=p["plugins"])
        lines = [status_line(s) for s in mem]
        for line in lines:
            work.event("collection", line)
        work.say({"role": "assistant", "content": "**Memory triage**\n\n```\n" + "\n".join(lines) + "\n```"})
    usable = [s for s in disk if s.get("state") != "NOT_STARTED"] + [s for s in mem if s.get("state") == "FINISHED"]
    if p.get("investigate") and usable and work.llm is not None:
        return {"triage": True, **_investigation(work, dossier.triage_note(disk + mem))}
    return {"triage": True}


def _decide(work: _Work) -> dict:
    """Carries out the investigator's decisions on waiting requests, then lets the agent go on with the results."""
    from copilot import approvals, cases, collection, citations
    from copilot.agent import status_line
    work.begin()
    done = 0
    for request_id, approved in work.payload.get("decisions") or []:
        request = approvals.claim(request_id, work.job_id, work.book)
        if not request:
            continue                      # decided in another page or job already
        done += 1
        label = approvals.describe(request)
        if not approved:
            approvals.resolve(request, False, actor=work.user)
            approvals.finish(request_id, "declined", work.user, conn=work.book)
            work.history.append(HumanMessage(content=f"[Investigator] Declined: {label}."))
            work.say({"role": "assistant", "content": f"❌ Declined — {citations.md_literal(label)}", "literal": True})
            continue
        work.event("status", f"{label}...")
        try:
            result, state = approvals.resolve(request, True, actor=work.user), "approved"
        except (approvals.ApprovalError, collection.CollectionError, cases.CaseError) as e:
            result, state = f"Failed: {e}", "failed"
        approvals.finish(request_id, state, work.user, result, conn=work.book)
        if isinstance(result, dict):    # a code block shows the status line as it is; it can't be closed early
            shown = "```\n" + status_line(result).replace("```", "'''") + "\n```"
            work.event("collection", status_line(result))
        else:
            shown = citations.md_literal(str(result))
        work.history.append(HumanMessage(content=f"[Investigator] Approved: {label}. "
                                                 f"Result: {json.dumps(result, default=str)}"))
        work.say({"role": "assistant", "literal": True, "content": f"✅ Approved — {citations.md_literal(label)}\n\n{shown}"
                  + ("" if work.payload.get("auto_continue", True) else "\n\nAsk the copilot to continue when ready.")})
    work.checkpoint()
    if done and work.payload.get("auto_continue", True) and work.llm is not None \
            and not approvals.pending(work.user, work.book) and cases.current_id() == work.case_id:
        return {"decided": done, **_turn(work, CONTINUE, show_user=False)}
    return {"decided": done}


HANDLERS = {"ask": _ask, "investigate": _investigate, "triage": _triage, "decide": _decide}
