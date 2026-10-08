from langchain_core.messages import AIMessage, HumanMessage

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
