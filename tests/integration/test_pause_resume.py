"""Cooperative pause/resume of the fix agent (checkpoint + sandbox lifecycle)."""

import httpx
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import SecretStr

from src.agent import runner
from src.agent.runner import run_fix_agent
from src.utils import retry as retry_mod
from tests.conftest import FakeContentSource
from tests.fakes import PASSING, FakePRService, FakeSandboxManager, failing
from tests.integration.test_graph_core_run import APP, INITIAL, MANIFEST
from tests.llm_helpers import Recorder, chat, good


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(runner.settings, "AUTOMATION_ENABLED", True)
    monkeypatch.setattr("src.agent.nodes.fix_generator.default_settings.LLM_API_KEY", SecretStr("k"))

    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def source():
    return FakeContentSource(files={"requirements.txt": MANIFEST, "app/client.py": APP}, search={"requests": ["app/client.py"]}, release_notes="n")


def fix(new="requests==2.32.0"):
    return chat(good(file_changes=[good()["file_changes"][0] | {"new_content": new}]))


class Harness:
    def __init__(self, agent_deps, rec, mgr=None):
        self.agent_deps, self.rec = agent_deps, rec
        self.mgr = mgr or FakeSandboxManager({"requirements.txt": MANIFEST, "app/client.py": APP})
        self.saver = InMemorySaver()
        self.pr = FakePRService()  # shared across runs: it stands for GitHub, which outlives a pause
        self.src = source()

    async def run(self, state=INITIAL, pause_when=None):
        async def should_pause():
            return bool(pause_when and pause_when(self))

        with self.agent_deps(self.src, llm_transport=httpx.MockTransport(self.rec), sandbox=self.mgr, pr=self.pr) as deps:
            self.deps = deps
            return await run_fix_agent(state["job_id"], state, checkpointer=self.saver, should_pause=should_pause)

    # observation helpers
    def pytest_runs(self) -> int:
        return sum(1 for sb in self.mgr.sandboxes.values() for c in sb.calls if "-m" in c and "pytest" in c)  # test runs, not the pip install


RUN1 = INITIAL | {"run_id": "run-1"}


async def test_pause_after_the_baseline_tests_frees_the_sandbox_and_resume_recreates_it(agent_deps):
    h = Harness(agent_deps, Recorder(fix()))
    paused = await h.run(RUN1, pause_when=lambda h: h.pytest_runs() >= 1)
    assert paused.terminal_status == "PAUSED" and paused.sandbox_container_id is None
    assert h.mgr.removed == [h.mgr.only.container_id]  # the sandbox is released while paused
    assert h.pr.created == [] and len(h.rec.requests) == 1

    final = await h.run(RUN1)  # resume (same run)
    assert final.terminal_status == "PR_RAISED" and final.error is None
    assert len(h.mgr.sandboxes) == 2  # a fresh sandbox, baseline re-validated
    assert len(h.rec.requests) == 1  # generate_fix is not repeated
    assert len(h.pr.created) == 1 and final.fix_attempt == 1
    types = [e["event_type"] for e in final.audit_events]
    assert types.count("CONTEXT_ASSEMBLED") == 1 and types.count("FIX_GENERATED") == 1 and types.count("SANDBOX_STARTED") == 2


async def test_pause_before_any_sandbox_just_continues_later(agent_deps):
    h = Harness(agent_deps, Recorder(fix()))
    paused = await h.run(RUN1, pause_when=lambda h: len(h.rec.requests) >= 1)  # right after generate_fix
    assert paused.terminal_status == "PAUSED" and h.mgr.sandboxes == {} and paused.file_changes
    final = await h.run(RUN1)
    assert final.terminal_status == "PR_RAISED" and len(h.rec.requests) == 1 and len(h.mgr.sandboxes) == 1


class RegressThenHeal(FakeSandboxManager):
    """First sandbox: baseline passes, the fix regresses. Every later sandbox: all green (the second attempt works)."""

    async def create(self, **kw):
        self._kwargs["pytest_outputs"] = [PASSING] if self.sandboxes else [PASSING, failing("test_login")]
        return await super().create(**kw)


async def test_pause_at_a_repair_boundary_keeps_the_failure_history(agent_deps):
    mgr = RegressThenHeal({"requirements.txt": MANIFEST, "app/client.py": APP})
    h = Harness(agent_deps, Recorder(fix("requests==2.32.0"), fix("requests==2.32.1")), mgr)
    # pause once the regression has been seen (pre + post test runs) and attempt 1 is about to be retried
    paused = await h.run(RUN1, pause_when=lambda h: h.pytest_runs() >= 2 and len(h.rec.requests) == 1)
    assert paused.terminal_status == "PAUSED" and len(paused.previous_attempts) == 1 and mgr.removed

    final = await h.run(RUN1)
    assert final.terminal_status == "PR_RAISED" and final.fix_attempt == 2 and len(h.rec.requests) == 2
    assert "test_login" in h.rec.bodies[1]["messages"][1]["content"]  # the retry still knows why attempt 1 failed
    assert len(mgr.sandboxes) == 2


async def test_pause_after_the_pr_exists_does_not_create_a_second_one(agent_deps):
    h = Harness(agent_deps, Recorder(fix()))
    paused = await h.run(RUN1, pause_when=lambda h: bool(h.pr.created))
    assert paused.terminal_status == "PAUSED" and paused.pr_url
    final = await h.run(RUN1)
    assert final.terminal_status == "PR_RAISED" and len(h.pr.created) == 1 and final.notification_results


async def test_a_new_run_id_starts_fresh_instead_of_resuming(agent_deps):
    h = Harness(agent_deps, Recorder(fix()))
    await h.run(RUN1, pause_when=lambda h: len(h.rec.requests) >= 1)
    final = await h.run(INITIAL | {"run_id": "run-2"})  # e.g. the job was re-queued later
    assert final.terminal_status == "PR_RAISED" and len(h.rec.requests) == 2  # everything ran again from the top
    assert final.run_id == "run-2"


async def test_no_pause_requested_behaves_as_before(agent_deps):
    h = Harness(agent_deps, Recorder(fix()))
    final = await h.run(RUN1)
    assert final.terminal_status == "PR_RAISED" and h.mgr.removed == [h.mgr.only.container_id]
