"""Run the real core graph (assemble -> reachability -> fix -> score -> sandbox stub) with fakes."""

import asyncio

import httpx
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.errors import NodeCancelledError
from pydantic import SecretStr

from src.agent import graph as graph_mod
from src.agent import runner
from src.agent.deps import override_deps
from src.agent.runner import run_fix_agent
from src.agent.state import AgentState
from src.utils import retry as retry_mod
from tests.conftest import FakeContentSource
from tests.llm_helpers import Recorder, chat, good

MANIFEST = "flask==3.0.0\nrequests==2.31.0\n"
APP = "import requests\n\ndef get():\n    return requests.get('https://x')\n"
INITIAL = {
    "job_id": "job-42", "cve_id": "CVE-2024-35195", "repo_name": "org/api-gateway", "ecosystem": "pip",
    "affected_package": "requests", "installed_version": "2.31.0", "target_version": "2.32.0",
    "manifest_file_path": "requirements.txt", "cvss_score": 5.6, "severity": "MEDIUM",
}  # fmt: skip


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(runner.settings, "AUTOMATION_ENABLED", True)
    monkeypatch.setattr("src.agent.nodes.fix_generator.default_settings.LLM_API_KEY", SecretStr("k"))

    async def _sleep(_: float) -> None:
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def source(**kw):
    base = dict(
        files={"requirements.txt": MANIFEST, "app/client.py": APP},
        search={"requests": ["app/client.py"]},
        release_notes="## 2.32.0\n- fix",
    )
    base.update(kw)
    return FakeContentSource(**base)


def event_types(state: AgentState) -> list[str]:
    return [e["event_type"] for e in state.audit_events]


async def run(agent_deps, src, rec, initial=INITIAL, saver=None, cve=None, sandbox=None):
    kwargs = {"cve": cve} if cve is not None else {}
    if sandbox is not None:
        kwargs["sandbox"] = sandbox
    with agent_deps(src, llm_transport=httpx.MockTransport(rec), **kwargs):
        return await run_fix_agent(initial["job_id"], initial, checkpointer=saver or InMemorySaver())


async def test_happy_path_raises_pr_and_notifies(agent_deps):
    rec = Recorder(chat(good()))
    final = await run(agent_deps, source(), rec)
    assert final.error is None and final.terminal_status == "PR_RAISED"
    assert final.reachable is True and final.fix_attempt == 1
    assert final.file_changes[0].new_content == "requests==2.32.0"
    # severity 11 + bump 25 + self-confidence 14 + advisory 10, then tests 25 and scanner 5
    assert final.confidence_score == 11 + 25 + 14 + 10 + 25 + 5
    assert final.confidence_breakdown["tests"] == 25 and final.confidence_breakdown["scanner"] == 5
    assert event_types(final) == [
        "CONTEXT_ASSEMBLED", "REACHABILITY_ASSESSED", "FIX_GENERATED", "CONFIDENCE_SCORED", "SANDBOX_STARTED",
        "PRE_TESTS_PASSED", "PATCH_APPLIED", "PATCH_APPLIED", "POST_TESTS_PASSED", "SCAN_CONFIRMED",
        "SANDBOX_REMOVED", "PR_RAISED", "NOTIFICATION_SENT",
    ]  # fmt: skip
    assert len(rec.requests) == 1


async def test_llm_garbage_ends_failed_via_handle_error(agent_deps):
    final = await run(agent_deps, source(), Recorder(chat("garbage")))
    assert final.terminal_status == "FAILED" and "valid fix" in final.error
    assert event_types(final)[-1] == "JOB_FAILED" and "CONFIDENCE_SCORED" not in event_types(final)


async def test_context_failure_never_calls_the_llm(agent_deps):
    rec = Recorder(chat(good()))
    final = await run(agent_deps, source(files={}), rec)
    assert final.terminal_status == "FAILED" and "manifest" in final.error
    assert rec.requests == [] and event_types(final) == ["JOB_FAILED"]


async def test_supply_chain_mismatch_stops_before_llm(agent_deps):
    rec = Recorder(chat(good()))
    final = await run(agent_deps, source(), rec, initial=INITIAL | {"target_version": "9.9.9"})
    assert "supply-chain" in final.error and rec.requests == []


async def test_low_confidence_routes_to_handle_error(agent_deps, monkeypatch):
    # code-only change (5) + zero self-confidence + low CVSS + unverified advisory -> 2 + 5 + 0 + 0 = 7 < 20
    monkeypatch.setattr("src.agent.nodes.context_assembler.settings.SUPPLY_CHAIN_VERIFY", False)
    change = {"file_path": "app/client.py", "change_description": "x",
              "original_content": "requests.get('https://x')", "new_content": "requests.get('https://x', timeout=3)"}  # fmt: skip
    initial = INITIAL | {"cvss_score": 1.0, "severity": "LOW", "target_version": "9.9.9"}
    final = await run(agent_deps, source(), Recorder(chat(good(file_changes=[change], self_confidence=0))), initial=initial)
    assert final.confidence_score == 7
    assert final.terminal_status == "FAILED" and "below the minimum of 20" in final.error
    assert event_types(final)[-2:] == ["CONFIDENCE_SCORED", "JOB_FAILED"]


async def test_unreachable_enforced_skips_llm(agent_deps, monkeypatch):
    monkeypatch.setattr("src.agent.nodes.reachability.settings.REACHABILITY_MODE", "enforce")
    rec = Recorder(chat(good()))
    src = source(files={"requirements.txt": MANIFEST, "app/other.py": "import os\n"}, search={"requests": ["app/other.py"]})
    final = await run(agent_deps, src, rec)
    assert final.terminal_status == "NOT_REACHABLE" and final.reachable is False
    assert rec.requests == [] and event_types(final)[-1] == "REACHABILITY_ASSESSED"


async def test_unreachable_advisory_still_fixes(agent_deps, monkeypatch):
    monkeypatch.setattr("src.agent.nodes.reachability.settings.REACHABILITY_MODE", "advisory")
    src = source(files={"requirements.txt": MANIFEST, "app/other.py": "import os\n"}, search={"requests": ["app/other.py"]})
    final = await run(agent_deps, src, Recorder(chat(good())))
    assert final.reachable is False and final.terminal_status == "PR_RAISED"


async def test_kill_switch_runs_nothing(agent_deps, monkeypatch):
    monkeypatch.setattr(runner.settings, "AUTOMATION_ENABLED", False)
    rec = Recorder(chat(good()))
    src = source()
    final = await run(agent_deps, src, rec)
    assert final.terminal_status == "DISABLED" and rec.requests == [] and src.calls == []


async def test_state_is_checkpointed_per_job(agent_deps):
    saver = InMemorySaver()
    await run(agent_deps, source(), Recorder(chat(good())), saver=saver)
    history = [c async for c in saver.alist({"configurable": {"thread_id": "job-42"}})]
    assert len(history) >= 10  # one checkpoint per superstep
    latest = history[0].checkpoint["channel_values"]
    assert latest["terminal_status"] == "PR_RAISED"


async def test_crashed_run_resumes_from_last_checkpoint(agent_deps, monkeypatch):
    """A hard crash after reachability resumes at generate_fix without redoing earlier nodes."""
    real = graph_mod.generate_fix
    crash = {"on": True}

    async def flaky(state):
        if crash["on"]:
            raise asyncio.CancelledError  # simulates the worker dying mid-node
        return await real(state)

    monkeypatch.setattr(graph_mod, "generate_fix", flaky)
    saver = InMemorySaver()
    src = source()
    with pytest.raises(NodeCancelledError):
        await run(agent_deps, src, Recorder(chat(good())), saver=saver)
    searches_before = sum(1 for name, _ in src.calls if name == "search_code")

    crash["on"] = False
    final = await run(agent_deps, src, Recorder(chat(good())), saver=saver)
    assert final.terminal_status == "PR_RAISED"
    assert sum(1 for name, _ in src.calls if name == "search_code") == searches_before  # context not rebuilt
    assert event_types(final).count("CONTEXT_ASSEMBLED") == 1
