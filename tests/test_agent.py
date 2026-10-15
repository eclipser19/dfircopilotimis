import json

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from copilot.agent import TokenUsage, _process_turn


class FakeLLM:
    """Always asks for another tool call and reports fixed token usage."""

    def __init__(self, tokens_per_call=1000, answer_after=None):
        self.calls = 0
        self.tokens = tokens_per_call
        self.answer_after = answer_after

    def invoke(self, history):
        self.calls += 1
        usage = {"input_tokens": self.tokens, "output_tokens": 0, "total_tokens": self.tokens}
        if self.answer_after and self.calls >= self.answer_after:
            return AIMessage(content="done", usage_metadata=usage)
        return AIMessage(content="", usage_metadata=usage,
                         tool_calls=[{"name": "case_summary", "args": {}, "id": f"c{self.calls}"}])


def test_token_budget_stops_the_turn(case, capsys):
    llm = FakeLLM(tokens_per_call=1000)
    usage = _process_turn(llm, [HumanMessage(content="go")], max_steps=50, max_tokens=3500)
    assert llm.calls == 4  # stops once 4,000 >= 3,500
    assert usage.turn_total == 4000
    assert "Token budget for this turn reached" in capsys.readouterr().out


def test_usage_accumulates_across_turns(case, capsys):
    usage = TokenUsage()
    _process_turn(FakeLLM(500, answer_after=2), [HumanMessage(content="a")], 10, usage)
    _process_turn(FakeLLM(500, answer_after=1), [HumanMessage(content="b")], 10, usage)
    assert usage.turn_total == 500
    assert usage.session_input == 1500
    out = capsys.readouterr().out
    assert "maximum tool steps" not in out
    assert "session: 1,500" in out


class FakeFinalizer:
    def __init__(self):
        self.calls = 0
        self.last_prompt = None

    def invoke(self, history):
        self.calls += 1
        self.last_prompt = history[-1].content
        return AIMessage(content="Summary of findings so far", usage_metadata={"input_tokens": 100, "output_tokens": 50,
                                                                               "total_tokens": 150})


def test_agent_wraps_up_before_budget_instead_of_stopping_silently(case, capsys):
    llm, fin = FakeLLM(tokens_per_call=1000), FakeFinalizer()
    _process_turn(llm, [HumanMessage(content="go")], max_steps=50, max_tokens=5000, finalizer=fin)
    assert llm.calls == 4          # 4,000 >= 80% of 5,000
    assert fin.calls == 1
    assert "Do not call any tools" in fin.last_prompt
    out = capsys.readouterr().out
    assert "Summary of findings so far" in out
    assert "Token budget for this turn reached" not in out


def test_collection_plan_accepts_names_and_parameters(monkeypatch):
    from copilot.case_config import case_config
    monkeypatch.setattr(case_config, "data", {"collect": [
        "Generic.Client.Info",
        {"artifact": "Windows.EventLogs.EvtxHunter", "parameters": {"IdRegex": "7045"}},
        {"parameters": {"no": "artifact"}},
    ]})
    assert case_config.collection_plan == [
        {"artifact": "Generic.Client.Info", "parameters": {}},
        {"artifact": "Windows.EventLogs.EvtxHunter", "parameters": {"IdRegex": "7045"}},
    ]


class SilentLLM:
    """A local server that reports no token usage."""

    def __init__(self):
        self.calls = 0

    def invoke(self, history):
        self.calls += 1
        return AIMessage(content="", tool_calls=[{"name": "case_summary", "args": {}, "id": f"c{self.calls}"}])


def test_usage_is_estimated_when_the_model_reports_none():
    usage = TokenUsage()
    usage.add(AIMessage(content="x" * 400), prompt_chars=4000)
    assert (usage.turn_input, usage.turn_output) == (1000, 100)
    assert usage.estimated and "estimated" in usage.summary()


def test_budget_still_applies_without_reported_usage(case, capsys):
    llm = SilentLLM()
    _process_turn(llm, [HumanMessage(content="x" * 40_000)], max_steps=50, max_tokens=25_000)
    assert 1 < llm.calls < 50                       # stopped by the estimated budget, not the step limit
    assert "Token budget for this turn reached" in capsys.readouterr().out


class NoToolChoice:
    def invoke(self, history):
        raise ValueError("tool_choice 'none' is not supported")


def test_wrap_up_falls_back_when_the_server_rejects_tool_choice(case, capsys):
    class Answers(FakeLLM):
        def invoke(self, history):
            if "Do not call any tools" in str(history[-1].content):
                return AIMessage(content="Wrapped up anyway", tool_calls=[{"name": "case_summary", "args": {},
                                                                           "id": "late"}])
            return super().invoke(history)

    history = [HumanMessage(content="go")]
    _process_turn(Answers(tokens_per_call=1000), history, max_steps=50, max_tokens=5000, finalizer=NoToolChoice())
    assert "Wrapped up anyway" in capsys.readouterr().out
    assert history[-1].content == "Wrapped up anyway" and not history[-1].tool_calls   # no dangling tool call


# ---- Conversations stay valid when a turn is cut short ----

def _valid(history):
    """What the model API checks: each tool call answered before anything else, no stray results."""
    pending = []
    for m in history:
        if isinstance(m, ToolMessage):
            assert m.tool_call_id in pending, f"stray tool result {m.tool_call_id}"
            pending.remove(m.tool_call_id)
            continue
        assert not pending, f"unanswered tool calls {pending}"
        if isinstance(m, AIMessage) and m.tool_calls:
            pending = [c["id"] for c in m.tool_calls]
    assert not pending
    return True


def test_repair_answers_dangling_tool_calls_and_drops_stray_results():
    from copilot.agent import INTERRUPTED, repair_history
    history = [SystemMessage("s"), HumanMessage("q"),
               AIMessage(content="", tool_calls=[{"name": "case_summary", "args": {}, "id": "a"},
                                                 {"name": "list_collections", "args": {}, "id": "b"}]),
               ToolMessage(content="ok", tool_call_id="a", name="case_summary"),
               HumanMessage("next question"),
               ToolMessage(content="late", tool_call_id="zzz", name="x")]
    repair_history(history)
    assert _valid(history)
    assert [m.content for m in history if isinstance(m, ToolMessage)] == ["ok", INTERRUPTED]
    assert history[4].tool_call_id == "b" and history[4].name == "list_collections"
    assert isinstance(history[5], HumanMessage)


class Stop(BaseException):
    """Like Streamlit's StopException / RerunException: not an Exception."""


def test_a_turn_stopped_mid_tool_leaves_a_valid_conversation(case, monkeypatch):
    from copilot import agent
    from copilot.agent import run_turn

    class Stopper:
        name = "case_summary"

        def invoke(self, args):
            raise Stop()

    monkeypatch.setitem(agent.tool_map, "case_summary", Stopper())
    history = [SystemMessage("s"), HumanMessage("go")]
    with pytest.raises(Stop):
        run_turn(FakeLLM(), history, max_steps=5, emit=lambda *a: None)
    assert isinstance(history[-1], ToolMessage) and _valid(history)


def test_a_broken_saved_conversation_is_repaired_when_loaded(case):
    from copilot import cases, conversation
    from langchain_core.messages import messages_to_dict
    broken = [HumanMessage("q"), AIMessage(content="", tool_calls=[{"name": "case_summary", "args": {}, "id": "x"}])]
    case.conn.execute("CREATE TABLE IF NOT EXISTS conversation (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)")
    case.conn.execute("INSERT OR REPLACE INTO conversation VALUES ('agent', ?, '')",
                      (json.dumps(messages_to_dict(broken)),))
    case.conn.commit()
    _, history = conversation.load(cases.current_id(), "system")
    assert _valid(history) and isinstance(history[-1], ToolMessage)


def test_agent_answers_when_its_tool_steps_run_out(case, capsys):
    # A question that used every step used to end with no answer at all.
    llm, fin = FakeLLM(tokens_per_call=10), FakeFinalizer()
    _process_turn(llm, [HumanMessage(content="go")], max_steps=3, max_tokens=100000, finalizer=fin)
    assert llm.calls == 3 and fin.calls == 1
    assert "tool-step budget" in fin.last_prompt
    out = capsys.readouterr().out
    assert "Summary of findings so far" in out and "Halting" not in out
