"""PR, notification and audit behaviour of the full graph (fake sandbox / GitHub / channels)."""

import httpx
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import SecretStr

from src.agent import runner
from src.agent.runner import run_fix_agent
from src.services.github.pr_creator import ExistingPR, PRConflictError
from src.utils import retry as retry_mod
from tests.conftest import FakeContentSource
from tests.fakes import FakePRService, FakeSandboxManager, MemoryAuditStore, RecordingHandler, failing, PASSING
from tests.integration.test_graph_core_run import APP, INITIAL, MANIFEST
from tests.llm_helpers import Recorder, chat, good


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(runner.settings, "AUTOMATION_ENABLED", True)
    monkeypatch.setattr("src.agent.nodes.fix_generator.default_settings.LLM_API_KEY", SecretStr("k"))

    async def _sleep(_: float) -> None:
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def source():
    return FakeContentSource(files={"requirements.txt": MANIFEST, "app/client.py": APP}, search={"requests": ["app/client.py"]}, release_notes="n")


def types(state):
    return [e["event_type"] for e in state.audit_events]


async def run(agent_deps, rec=None, saver=None, **deps_kw):
    rec = rec or Recorder(chat(good()))
    with agent_deps(source(), llm_transport=httpx.MockTransport(rec), **deps_kw) as deps:
        final = await run_fix_agent(INITIAL["job_id"], INITIAL, checkpointer=saver or InMemorySaver())
    return final, deps, rec


async def test_happy_path_pr_notification_and_audit(agent_deps):
    final, deps, _ = await run(agent_deps)
    assert final.terminal_status == "PR_RAISED" and final.pr_number == 101 and final.pr_url.endswith("/pull/101")
    (call,) = deps.pr.created
    assert call["repo"] == "org/api-gateway" and call["changes"][0].new_content == "requests==2.32.0"
    assert call["users"] == ["alice"] and call["teams"] == ["org/platform"]
    assert "### Confidence Score: 90 / 100" in call["body"] and "| Passed | 4 | 4 |" in call["body"]

    (teams,) = deps.handlers
    assert teams.attempts == 1 and teams.sent[0].metadata["pr_url"] == final.pr_url
    assert final.notification_results == [{"channel": "teams", "status": "sent", "error": None}]

    summary, events = deps.audit.flushed[INITIAL["job_id"]]
    assert summary.terminal_status == "PR_RAISED" and summary.pr_url == final.pr_url and summary.confidence_score == 90
    assert [e["event_type"] for e in events] == types(final)
    assert types(final)[-3:] == ["SANDBOX_REMOVED", "PR_RAISED", "NOTIFICATION_SENT"]


async def test_existing_bot_pr_is_not_duplicated_or_announced_again(agent_deps):
    existing = ExistingPR("https://github.com/org/api-gateway/pull/5", 5, "fix/cve-CVE-2024-35195-api-gateway-20261001", "older-job")
    final, deps, _ = await run(agent_deps, pr=FakePRService(existing=existing))
    assert final.terminal_status == "PR_EXISTS" and final.pr_url.endswith("/pull/5") and deps.pr.created == []
    assert deps.handlers[0].attempts == 0
    assert types(final)[-1] == "PR_DEDUPLICATED" and deps.audit.flushed[INITIAL["job_id"]][0].terminal_status == "PR_EXISTS"


async def test_base_branch_moved_fails_cleanly_but_is_still_audited(agent_deps):
    final, deps, _ = await run(agent_deps, pr=FakePRService(create_error=PRConflictError("found 0 matches")))
    assert final.terminal_status == "FAILED" and "cannot raise PR" in final.error
    assert deps.handlers[0].attempts == 0
    summary, events = deps.audit.flushed[INITIAL["job_id"]]
    assert summary.terminal_status == "FAILED" and events[-1]["event_type"] == "JOB_FAILED"


async def test_notification_outage_does_not_demote_the_pr(agent_deps):
    final, deps, _ = await run(agent_deps, handlers=[RecordingHandler("teams", fail_times=99)])
    assert final.terminal_status == "PR_RAISED" and final.error is None
    assert final.notification_results[0]["status"] == "failed"
    assert deps.audit.flushed[INITIAL["job_id"]][0].terminal_status == "PR_RAISED"


async def test_blocked_job_is_audited_without_pr_or_notification(agent_deps):
    mgr = FakeSandboxManager({"requirements.txt": MANIFEST, "app/client.py": APP}, pytest_outputs=[PASSING, failing("test_login")])
    final, deps, _ = await run(agent_deps, sandbox=mgr)
    assert final.terminal_status == "BLOCKED" and deps.pr.created == [] and deps.handlers[0].attempts == 0
    summary, events = deps.audit.flushed[INITIAL["job_id"]]
    assert summary.terminal_status == "BLOCKED" and summary.attempt_count == 3
    assert events[-1]["event_type"] == "JOB_BLOCKED" and sum(e["event_type"] == "FIX_ATTEMPT_FAILED" for e in events) == 3


async def test_not_reachable_job_is_audited(agent_deps, monkeypatch):
    monkeypatch.setattr("src.agent.nodes.reachability.settings.REACHABILITY_MODE", "enforce")
    src = FakeContentSource(files={"requirements.txt": MANIFEST, "app/other.py": "import os\n"}, search={"requests": ["app/other.py"]})
    with agent_deps(src, llm_transport=httpx.MockTransport(Recorder(chat(good())))) as deps:
        final = await run_fix_agent(INITIAL["job_id"], INITIAL, checkpointer=InMemorySaver())
    assert final.terminal_status == "NOT_REACHABLE" and deps.audit.flushed[INITIAL["job_id"]][0].terminal_status == "NOT_REACHABLE"


async def test_audit_failure_resumes_at_write_audit_without_repeating_side_effects(agent_deps):
    saver, audit = InMemorySaver(), MemoryAuditStore()
    audit.fail_times = 1
    pr, rec = FakePRService(), Recorder(chat(good()))

    with pytest.raises(RuntimeError, match="database unavailable"):
        await run(agent_deps, rec=rec, saver=saver, audit=audit, pr=pr)
    assert len(pr.created) == 1 and audit.flushed == {}

    final, deps, _ = await run(agent_deps, rec=rec, saver=saver, audit=audit, pr=pr)  # the Celery retry
    assert final.terminal_status == "PR_RAISED"
    assert len(pr.created) == 1 and len(rec.requests) == 1  # no second PR, no second LLM call
    assert audit.attempts == 2 and list(audit.flushed) == [INITIAL["job_id"]]
    assert types(final).count("PR_RAISED") == 1 and types(final).count("NOTIFICATION_SENT") == 1
