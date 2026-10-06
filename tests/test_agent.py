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
