from src.agent.nodes._common import NodeError, agent_node, make_event
from src.agent.nodes.handle_error import handle_error


async def test_marks_failed_and_records_event(make_state):
    out = await handle_error(make_state(error="LLM exploded", fix_attempt=2))
    assert out["terminal_status"] == "FAILED" and out["error"] == "LLM exploded"
    event = out["audit_events"][-1]
    assert event["event_type"] == "JOB_FAILED" and event["payload"]["fix_attempt"] == 2


async def test_low_confidence_route_gets_an_explanation(make_state):
    out = await handle_error(make_state(confidence_score=12))
    assert "below the minimum of 20" in out["error"] and out["terminal_status"] == "FAILED"


async def test_previous_events_are_preserved_not_mutated(make_state):
    prior = [make_event("CONTEXT_ASSEMBLED")]
    state = make_state(error="x", audit_events=prior)
    out = await handle_error(state)
    assert [e["event_type"] for e in out["audit_events"]] == ["CONTEXT_ASSEMBLED", "JOB_FAILED"]
    assert len(state.audit_events) == 1


async def test_agent_node_converts_exceptions(make_state):
    @agent_node("boom")
    async def boom(state):
        raise RuntimeError("kaput")

    @agent_node("expected")
    async def expected(state):
        raise NodeError("clear message")

    out = await boom(make_state())
    assert out == {"error": "boom: RuntimeError: kaput", "terminal_status": "FAILED"}
    assert (await expected(make_state())) == {"error": "clear message", "terminal_status": "FAILED"}


def test_make_event_redacts_payload():
    ev = make_event("X", {"note": "token=abcdef123456"})
    assert "abcdef123456" not in str(ev) and ev["ts"]
