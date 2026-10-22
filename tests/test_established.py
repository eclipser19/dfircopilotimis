"""What earlier answers established reaches later conversations of the case (copilot/established.py)."""
from langchain_core.messages import AIMessage

from copilot import established
from copilot.case_config import case_config
from copilot.prompts import build_system_prompt


def _ids(case, n=3):
    case.ingest_artifact_results([{"EventTime": f"2024-02-06T20:1{i}:00Z", "Message": f"event {i}"} for i in range(n)],
                                 "S", "H", "C.1")
    return [e["evidence_id"] for e in case.query_timeline()["events"]]


def test_an_answer_keeps_what_the_dossier_does_not_cite_and_its_empty_searches(case):
    old, new, other = _ids(case)
    case.save_dossier(f"## Timeline\n- something (`{old}`)\n## Gaps\n- none")
    answer = (f"## Findings\n"
              f"- **Already known:** the dossier's step (`{old}`).\n"
              f"- **New:** `http://203.0.113.9/payload.exe` was downloaded, per memory (`{new}`).\n"
              f"- Garbled: `{'f' * 16}` is no record.\n"
              f"```text\nnet user x (`{other}`)\n```\n"
              f"Searches for 4732, 4728 and 4756 returned no matching records.\n"
              f"No evidence was found of:\n"
              f"The service binary does not prove execution.\n"
              f"- The process held a connection to 198.51.100.4:443.\n"
              f"  Evidence: `{other}`\n")
    found = established.extract(answer, case)
    assert [(s["kind"], s["evidence_ids"]) for s in found] == [("fact", [new]), ("not_found", []), ("fact", [other])]
    assert found[2]["text"] == "The process held a connection to 198.51.100.4:443."     # the IDs' own line joins it
    assert found[0]["text"].startswith("New: `http://203.0.113.9/payload.exe` was downloaded")
    assert found[1]["text"].startswith("Searches for 4732")


def test_later_conversations_start_from_it_until_a_new_dossier(case):
    old, new, _ = _ids(case)
    case.save_dossier(f"## Timeline\n- something (`{old}`)\n## Gaps\n- none")
    assert established.record("Where did the payload come from?", f"- Downloaded from 203.0.113.9 (`{new}`).") == 1
    assert established.record("And again?", f"- Downloaded from 203.0.113.9 (`{new}`).") == 0   # nothing new
    prompt = build_system_prompt(case_config)
    assert "## ESTABLISHED IN EARLIER ANSWERS" in prompt and "say that your answer corrects the earlier answer" in prompt
    assert f'- Asked "Where did the payload come from?":\n  - Downloaded from 203.0.113.9 (`{new}`).' in prompt
    assert prompt.index("## CASE DOSSIER") < prompt.index("## ESTABLISHED IN EARLIER ANSWERS")
    case.save_dossier(f"## Timeline\n- downloaded (`{new}`)\n## Gaps\n- none")     # a new dossier takes them in
    assert established.statements(case) == [] and "ESTABLISHED IN EARLIER" not in build_system_prompt(case_config)


def test_the_section_keeps_the_latest_answers_when_too_long(case, monkeypatch):
    ids = _ids(case, 6)
    monkeypatch.setattr(established, "PROMPT_CHARS", 200)
    for n, eid in enumerate(ids):
        established.record(f"question {n}", f"- statement {n} " + "x" * 60 + f" (`{eid}`)")
    section = established.prompt_section(case)
    assert "question 5" in section and "question 0" not in section and "earlier answers left out for length" in section


def test_questions_asked_in_the_app_and_the_benchmark_share_it(case):
    from copilot import benchmark, jobs
    _, new, later = _ids(case)

    class Scripted:
        def __init__(self, text):
            self.text, self.prompts = text, []

        def invoke(self, history):
            self.prompts.append(history[0].content)
            return AIMessage(content=self.text)
    jobs.wait(jobs.submit("ask", {"text": "where from?"}, Scripted(f"- From 203.0.113.9 (`{new}`)."), None))
    assert [s["question"] for s in established.statements(case)] == ["where from?"]
    second = Scripted(f"- Also 198.51.100.4 (`{later}`).")
    benchmark.ask("and then?", second, None, log=lambda *a: None)
    assert f"From 203.0.113.9 (`{new}`)" in second.prompts[0]                  # the benchmark's next question sees it
    assert [s["question"] for s in established.statements(case)] == ["where from?", "and then?"]
