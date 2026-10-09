"""The Celery -> LangGraph bridge: claiming, repo locking, retries, and giving up."""

import uuid
from types import SimpleNamespace

import pytest
import redis.asyncio as aioredis
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select

from src.core.config import settings
from src.core.database import session_scope
from src.models.cve import CVE
from src.models.job import JobStatus, RemediationJob, Repo
from src.utils.redis_locks import LockBusyError, RedisLock
from src.workers.tasks import remediation_tasks as rt

STATE = {"repo_name": "org/api", "cve_id": "CVE-2024-35195"}


@pytest.fixture
async def env(monkeypatch):
    base = settings.REDIS_URL.rsplit("/", 1)[0]
    monkeypatch.setattr(settings, "REDIS_URL", f"{base}/13")
    monkeypatch.setattr(settings, "AUTOMATION_ENABLED", True)
    client = aioredis.from_url(settings.REDIS_URL)
    try:
        await client.ping()
    except Exception:
        pytest.skip("Redis not reachable")
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


async def make_job(status=JobStatus.QUEUED) -> str:
    async with session_scope() as s:
        s.add(CVE(cve_id="CVE-2024-35195", source="NVD", raw_data={}))
        repo = Repo(full_name="org/api")
        s.add(repo)
        await s.flush()
        job = RemediationJob(job_id=uuid.uuid4(), cve_id="CVE-2024-35195", repo_id=repo.id, repo_name="org/api", status=status,
                             affected_package="requests", installed_version="2.31.0", target_version="2.32.0", manifest_file="requirements.txt")  # fmt: skip
        s.add(job)
        return str(job.job_id)


async def status_of(job_id) -> JobStatus:
    async with session_scope() as s:
        return (await s.get(RemediationJob, uuid.UUID(job_id))).status


class FakeAgent:
    def __init__(self, error: Exception | None = None):
        self.calls, self.error = [], error

    async def __call__(self, job_id, state, should_pause=None):
        self.calls.append((job_id, state))
        self.should_pause = should_pause
        if self.error:
            raise self.error
        return SimpleNamespace(terminal_status="PR_RAISED", pr_url="https://github.com/org/api/pull/7")


@pytest.mark.db
async def test_queued_job_is_claimed_and_run(migrated_db, env, monkeypatch):
    job_id, agent = await make_job(), FakeAgent()
    monkeypatch.setattr(rt, "run_fix_agent", agent)
    out = await rt.execute_job(job_id, STATE, resuming=False)
    assert out == {"job_id": job_id, "terminal_status": "PR_RAISED", "pr_url": "https://github.com/org/api/pull/7"}
    assert agent.calls == [(job_id, STATE | {"jira_issue_key": None, "confluence_page_url": None})]
    assert await status_of(job_id) == JobStatus.RUNNING
    assert await env.get("cve-remediation:repo-lock:org/api") is None  # lock released


@pytest.mark.db
async def test_duplicate_message_does_not_run_the_job_twice(migrated_db, env, monkeypatch):
    job_id, agent = await make_job(), FakeAgent()
    monkeypatch.setattr(rt, "run_fix_agent", agent)
    await rt.execute_job(job_id, STATE, resuming=False)
    again = await rt.execute_job(job_id, STATE, resuming=False)  # e.g. broker redelivery
    assert again["skipped"] == "job is not queued" and len(agent.calls) == 1


@pytest.mark.db
async def test_a_celery_retry_may_resume_its_own_running_job(migrated_db, env, monkeypatch):
    job_id, agent = await make_job(JobStatus.RUNNING), FakeAgent()
    monkeypatch.setattr(rt, "run_fix_agent", agent)
    assert (await rt.execute_job(job_id, STATE, resuming=True))["terminal_status"] == "PR_RAISED" and len(agent.calls) == 1


@pytest.mark.db
@pytest.mark.parametrize("status", [JobStatus.MERGED, JobStatus.BLOCKED, JobStatus.PR_RAISED, JobStatus.CANCELLED])
async def test_finished_jobs_are_never_rerun_even_on_retry(migrated_db, env, monkeypatch, status):
    job_id, agent = await make_job(status), FakeAgent()
    monkeypatch.setattr(rt, "run_fix_agent", agent)
    assert (await rt.execute_job(job_id, STATE, resuming=True))["skipped"] and agent.calls == []


@pytest.mark.db
async def test_busy_repo_defers_the_job_without_claiming_it(migrated_db, env, monkeypatch):
    job_id, agent = await make_job(), FakeAgent()
    monkeypatch.setattr(rt, "run_fix_agent", agent)
    other = RedisLock(env, "cve-remediation:repo-lock:org/api", 60)
    assert await other.acquire()  # another job is working on this repo
    with pytest.raises(LockBusyError):
        await rt.execute_job(job_id, STATE, resuming=False)
    assert agent.calls == [] and await status_of(job_id) == JobStatus.QUEUED
    await other.release()
    assert (await rt.execute_job(job_id, STATE, resuming=False))["terminal_status"] == "PR_RAISED"


@pytest.mark.db
async def test_agent_crash_keeps_the_job_running_for_the_retry_and_frees_the_lock(migrated_db, env, monkeypatch):
    job_id = await make_job()
    monkeypatch.setattr(rt, "run_fix_agent", FakeAgent(RuntimeError("database unavailable")))
    with pytest.raises(RuntimeError):
        await rt.execute_job(job_id, STATE, resuming=False)
    assert await status_of(job_id) == JobStatus.RUNNING and await env.get("cve-remediation:repo-lock:org/api") is None
    agent = FakeAgent()
    monkeypatch.setattr(rt, "run_fix_agent", agent)
    assert (await rt.execute_job(job_id, STATE, resuming=True))["terminal_status"] == "PR_RAISED"  # retry resumes


@pytest.mark.db
async def test_kill_switch_leaves_the_job_queued(migrated_db, env, monkeypatch):
    job_id, agent = await make_job(), FakeAgent()
    monkeypatch.setattr(rt, "run_fix_agent", agent)
    monkeypatch.setattr(settings, "AUTOMATION_ENABLED", False)
    assert (await rt.execute_job(job_id, STATE, resuming=False))["skipped"] == "automation disabled"
    assert agent.calls == [] and await status_of(job_id) == JobStatus.QUEUED


@pytest.mark.db
async def test_mark_job_failed_only_touches_running_jobs(migrated_db):
    running, merged = await make_job(JobStatus.RUNNING), None
    await rt.mark_job_failed(running)
    assert await status_of(running) == JobStatus.FAILED


@pytest.mark.db
async def test_mark_job_failed_leaves_merged_alone(migrated_db):
    job_id = await make_job(JobStatus.MERGED)
    await rt.mark_job_failed(job_id)
    assert await status_of(job_id) == JobStatus.MERGED


# ------------------------------------------------------------------ the Celery task wrapper (control flow only)
class Script:
    """Replaces ``run_async``: scripted outcomes for execute_job, recording every call."""

    def __init__(self, *outcomes):
        self.outcomes, self.calls = list(outcomes), []

    def __call__(self, fn, *args, **kwargs):
        self.calls.append((fn.__name__, args))
        if fn.__name__ == "mark_job_failed":
            return None
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def run_task(script, monkeypatch):
    monkeypatch.setattr(rt, "run_async", script)
    return rt.run_fix_agent_task.apply(args=["job-1", STATE], throw=False)


def executes(script):
    return [a for name, a in script.calls if name == "execute_job"]


def test_success_passes_the_result_through(monkeypatch):
    script = Script({"job_id": "job-1", "terminal_status": "PR_RAISED"})
    res = run_task(script, monkeypatch)
    assert res.successful() and res.result["terminal_status"] == "PR_RAISED" and executes(script) == [("job-1", STATE, False)]


def test_busy_repo_retries_later_without_counting_as_a_failure(monkeypatch):
    script = Script(LockBusyError("busy"), LockBusyError("busy"), {"terminal_status": "PR_RAISED"})
    res = run_task(script, monkeypatch)
    assert res.successful() and len(executes(script)) == 3
    assert [a[2] for a in executes(script)] == [False, True, True]  # 'resuming' once it has been retried
    assert not any(n == "mark_job_failed" for n, _ in script.calls)


def test_errors_are_retried_then_the_job_is_marked_failed(monkeypatch):
    script = Script(ConnectionError("db down"))
    res = run_task(script, monkeypatch)
    assert res.failed() and len(executes(script)) == rt.FAILURE_MAX_RETRIES + 1  # first try + retries
    assert [n for n, _ in script.calls].count("mark_job_failed") == 1 and script.calls[-1] == ("mark_job_failed", ("job-1",))


def test_a_transient_error_then_success(monkeypatch):
    script = Script(ConnectionError("blip"), {"terminal_status": "PR_RAISED"})
    res = run_task(script, monkeypatch)
    assert res.successful() and len(executes(script)) == 2 and not any(n == "mark_job_failed" for n, _ in script.calls)


def test_lock_waits_do_not_use_up_the_failure_budget(monkeypatch):
    busy = [LockBusyError("busy")] * 5
    script = Script(*busy, ConnectionError("x"), ConnectionError("x"), {"terminal_status": "PR_RAISED"})
    res = run_task(script, monkeypatch)
    assert res.successful() and len(executes(script)) == 8  # 5 waits + 2 failures (< 3) + success


def test_soft_time_limit_marks_the_job_failed(monkeypatch):
    script = Script(SoftTimeLimitExceeded())
    res = run_task(script, monkeypatch)
    assert res.failed() and script.calls[-1] == ("mark_job_failed", ("job-1",))



@pytest.mark.db
async def test_the_agent_is_given_a_live_pause_check(migrated_db, env, monkeypatch):
    job_id, agent = await make_job(), FakeAgent()
    monkeypatch.setattr(rt, "run_fix_agent", agent)
    await rt.execute_job(job_id, STATE, resuming=False)
    check = agent.should_pause
    assert await check() is False  # RUNNING
    async with session_scope() as s:
        (await s.get(RemediationJob, uuid.UUID(job_id))).status = JobStatus.PAUSED  # what the Control API does
    assert await check() is True
