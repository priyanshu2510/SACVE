"""Full graph with a fake sandbox: the agentic repair loop and every early-exit path."""

import httpx
import pytest
from pydantic import SecretStr

from src.agent import runner
from src.agent.runner import run_fix_agent
from src.services.sandbox.base import ExecResult
from src.utils import retry as retry_mod
from tests.conftest import FakeContentSource
from tests.fakes import PASSING, FakeSandboxManager, failing
from tests.integration.test_graph_core_run import APP, INITIAL, MANIFEST
from tests.llm_helpers import Recorder, chat, good
from langgraph.checkpoint.memory import InMemorySaver


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(runner.settings, "AUTOMATION_ENABLED", True)
    monkeypatch.setattr("src.agent.nodes.fix_generator.default_settings.LLM_API_KEY", SecretStr("k"))

    async def _sleep(_: float) -> None:
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def source():
    return FakeContentSource(
        files={"requirements.txt": MANIFEST, "app/client.py": APP}, search={"requests": ["app/client.py"]},
        release_notes="## 2.32.0",
    )  # fmt: skip


def fix(new: str = "requests==2.32.0"):
    change = good()["file_changes"][0] | {"new_content": new}
    return chat(good(file_changes=[change]))


async def run(agent_deps, rec, mgr, initial=INITIAL):
    src = source()
    with agent_deps(src, llm_transport=httpx.MockTransport(rec), sandbox=mgr):
        return await run_fix_agent(initial["job_id"], initial, checkpointer=InMemorySaver())


def types(state):
    return [e["event_type"] for e in state.audit_events]


def mgr_for(**kw):
    return FakeSandboxManager({"requirements.txt": MANIFEST, "app/client.py": APP}, **kw)


async def test_regression_is_repaired_on_second_attempt(agent_deps):
    mgr = mgr_for(pytest_outputs=[PASSING, failing("test_login"), PASSING])  # pre, post#1, post#2
    rec = Recorder(fix("requests==2.32.0"), fix("requests==2.32.1"))
    final = await run(agent_deps, rec, mgr)

    assert final.terminal_status == "PR_RAISED" and final.fix_attempt == 2
    assert final.test_delta_passed is True and final.scanner_cve_resolved is True
    assert len(mgr.sandboxes) == 1 and mgr.sandboxes[mgr.removed[0]] is mgr.only  # one sandbox, reused, removed once
    assert mgr.only.resets == 2  # apply_patch reset the workspace before each attempt
    assert len(final.previous_attempts) == 1 and "test_login" in final.previous_attempts[0]["failure_reason"]
    # the second LLM call was told what went wrong
    second_prompt = rec.bodies[1]["messages"][1]["content"]
    assert "PREVIOUS ATTEMPTS THAT FAILED" in second_prompt and "test_login" in second_prompt
    assert mgr.only.files["requirements.txt"] == "flask==3.0.0\nrequests==2.32.1\n"
    assert types(final).count("FIX_GENERATED") == 2 and "FIX_ATTEMPT_FAILED" in types(final)
    assert final.failure_reason is None and final.confidence_score == 90  # rescored for attempt 2


async def test_attempts_exhausted_ends_blocked_without_pr(agent_deps):
    mgr = mgr_for(pytest_outputs=[PASSING, failing("test_login")])  # every post run regresses
    rec = Recorder(fix("requests==2.32.0"), fix("requests==2.32.1"), fix("requests==2.32.2"))
    final = await run(agent_deps, rec, mgr)

    assert final.terminal_status == "BLOCKED" and final.fix_attempt == 3 and len(rec.requests) == 3
    assert "test_login" in final.failure_reason and len(final.previous_attempts) == 3
    assert mgr.removed == [mgr.only.container_id] and final.sandbox_container_id is None
    assert "PR_RAISED" not in types(final) and types(final)[-2:] == ["SANDBOX_REMOVED", "JOB_BLOCKED"]


async def test_max_fix_attempts_is_honoured(agent_deps):
    mgr = mgr_for(pytest_outputs=[PASSING, failing("test_x")])
    rec = Recorder(fix())
    final = await run(agent_deps, rec, mgr, initial=INITIAL | {"max_fix_attempts": 1})
    assert final.terminal_status == "BLOCKED" and len(rec.requests) == 1


async def test_cve_still_present_triggers_repair_then_blocks(agent_deps):
    mgr = mgr_for(scan_always_vulnerable=True)
    final = await run(agent_deps, Recorder(fix()), mgr)
    assert final.terminal_status == "BLOCKED" and final.fix_attempt == 3
    assert "still reported by the scanner" in final.failure_reason and final.scanner_cve_resolved is False


async def test_dependency_conflict_triggers_repair(agent_deps):
    mgr = mgr_for(install_results=[ExecResult(0, ""), ExecResult(1, "ResolutionImpossible"), ExecResult(0, "")])
    final = await run(agent_deps, Recorder(fix("requests==2.32.0"), fix("requests==2.32.1")), mgr)
    assert final.terminal_status == "PR_RAISED" and final.fix_attempt == 2
    assert "ResolutionImpossible" in final.previous_attempts[0]["failure_reason"]


async def test_patch_that_does_not_apply_is_retried(agent_deps):
    # repo in the sandbox differs from what the LLM saw, so original_content does not match there
    mgr = FakeSandboxManager({"requirements.txt": "flask==3.0.0\nrequests==2.31.1\n", "app/client.py": APP})
    final = await run(agent_deps, Recorder(fix()), mgr)
    assert final.terminal_status == "BLOCKED" and "was not found" in final.failure_reason
    assert types(final).count("FIX_GENERATED") == 3 and "PATCH_APPLIED" not in types(final)


async def test_failing_baseline_never_patches(agent_deps):
    mgr = mgr_for(pytest_outputs=[failing("test_a")])
    rec = Recorder(fix())
    final = await run(agent_deps, rec, mgr)
    assert final.terminal_status == "BASELINE_FAILING" and final.fix_attempt == 1 and len(rec.requests) == 1
    assert mgr.removed == [mgr.only.container_id]
    assert "PATCH_APPLIED" not in types(final) and mgr.only.resets == 0


async def test_baseline_install_failure(agent_deps):
    mgr = mgr_for(install_results=[ExecResult(1, "no matching distribution")])
    final = await run(agent_deps, Recorder(fix()), mgr)
    assert final.terminal_status == "BASELINE_FAILING" and mgr.removed == [mgr.only.container_id]


async def test_repo_without_tests_is_not_validated(agent_deps):
    mgr = mgr_for(pytest_outputs=["no tests ran in 0.01s"])
    final = await run(agent_deps, Recorder(fix()), mgr)
    assert final.terminal_status == "NO_TESTS" and mgr.removed


async def test_network_disabled_fails_cleanly(agent_deps):
    mgr = mgr_for(network_enabled=False)
    final = await run(agent_deps, Recorder(fix()), mgr)
    assert final.terminal_status == "FAILED" and "network disabled" in final.error
    assert mgr.removed == [mgr.only.container_id] and types(final)[-1] == "JOB_FAILED"


async def test_sandbox_creation_failure(agent_deps):
    mgr = mgr_for()
    from src.services.sandbox.base import SandboxError

    mgr.create_error = SandboxError("docker daemon unreachable")
    final = await run(agent_deps, Recorder(fix()), mgr)
    assert final.terminal_status == "FAILED" and "docker daemon unreachable" in final.error and mgr.removed == []


async def test_scanner_outage_is_a_hard_failure_not_a_retry(agent_deps):
    mgr = mgr_for(scan_error=True)
    rec = Recorder(fix())
    final = await run(agent_deps, rec, mgr)
    assert final.terminal_status == "FAILED" and "grype failed" in final.error and len(rec.requests) == 1
    assert mgr.removed == [mgr.only.container_id]
