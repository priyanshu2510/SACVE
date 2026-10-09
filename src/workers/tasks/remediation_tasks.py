"""Celery -> LangGraph bridge: runs the fix agent for one ``{cve, repo}`` job."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import redis.asyncio as aioredis
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import update

from src.agent.runner import run_fix_agent
from src.core.config import settings
from src.core.database import session_scope
from src.models.job import JobStatus, RemediationJob
from src.services.tracking import TrackingService
from src.utils.redis_locks import LockBusyError, repo_lock
from src.workers.celery_app import REMEDIATION_HARD_LIMIT_SECONDS, REMEDIATION_SOFT_LIMIT_SECONDS, celery_app
from src.workers.runtime import run_async

log = structlog.get_logger(__name__)

LOCK_RETRY_SECONDS = 300
LOCK_MAX_RETRIES = 36  # waits up to ~3 h for a repo that another job is working on
FAILURE_MAX_RETRIES = 3


async def _claim(job_id: str, resuming: bool) -> bool:
    """Atomically move the job to RUNNING. A Celery retry (``resuming``) may re-claim its own RUNNING job."""
    import uuid

    allowed = [JobStatus.QUEUED, JobStatus.RUNNING] if resuming else [JobStatus.QUEUED]
    async with session_scope() as s:
        result = await s.execute(
            update(RemediationJob)
            .where(RemediationJob.job_id == uuid.UUID(job_id), RemediationJob.status.in_(allowed))
            .values(status=JobStatus.RUNNING)
            .returning(RemediationJob.job_id)
        )
        return result.first() is not None


def pause_requested(job_id: str) -> Callable[[], Awaitable[bool]]:
    """Poll for a pause: the Control API sets the job to PAUSED, the runner checks between graph steps."""
    import uuid

    async def _check() -> bool:
        async with session_scope() as s:
            row = await s.get(RemediationJob, uuid.UUID(job_id))
            return row is not None and row.status == JobStatus.PAUSED

    return _check


async def mark_job_failed(job_id: str) -> None:
    """Last resort when Celery gives up: do not leave the job RUNNING forever."""
    import uuid

    async with session_scope() as s:
        await s.execute(
            update(RemediationJob)
            .where(RemediationJob.job_id == uuid.UUID(job_id), RemediationJob.status == JobStatus.RUNNING)
            .values(status=JobStatus.FAILED)
        )


async def execute_job(job_id: str, initial_state: dict[str, Any], resuming: bool) -> dict[str, Any]:
    """Serialise per repo, claim the job, then run the graph (resuming from its checkpoint if it crashed)."""
    if not settings.AUTOMATION_ENABLED:
        log.warning("remediation.skipped", reason="AUTOMATION_ENABLED=false", job_id=job_id)
        return {"job_id": job_id, "skipped": "automation disabled"}
    client = aioredis.from_url(settings.REDIS_URL)
    try:
        async with repo_lock(client, initial_state["repo_name"], settings.REPO_LOCK_TTL_SECONDS):
            if not await _claim(job_id, resuming):
                log.info("remediation.not_claimable", job_id=job_id)
                return {"job_id": job_id, "skipped": "job is not queued"}
            refs = await TrackingService.from_settings().ensure(job_id)  # best effort; lets the PR link to JIRA/Confluence
            state = {**initial_state, "jira_issue_key": refs.jira_issue_key, "confluence_page_url": refs.confluence_page_url}
            final = await run_fix_agent(job_id, state, should_pause=pause_requested(job_id))
    finally:
        await client.aclose()
    return {"job_id": job_id, "terminal_status": final.terminal_status, "pr_url": final.pr_url}


@celery_app.task(
    name="remediation.run_fix_agent",
    bind=True,
    max_retries=LOCK_MAX_RETRIES + FAILURE_MAX_RETRIES,  # Celery's counter is shared; failures are tracked separately
    acks_late=True,
    soft_time_limit=REMEDIATION_SOFT_LIMIT_SECONDS,
    time_limit=REMEDIATION_HARD_LIMIT_SECONDS,
)
def run_fix_agent_task(self: Any, job_id: str, initial_state: dict[str, Any], failures: int = 0) -> dict[str, Any]:
    """Boot and run the LangGraph fix agent for one job.

    * Another job on the same repo holds the lock -> retry later (no work lost).
    * An exception (e.g. the audit flush failed) -> retry with backoff (``failures`` counts these
      separately from lock waits); the graph resumes from its last checkpoint, so completed steps
      (and PRs) are never repeated.
    * Out of retries -> the job is marked FAILED instead of staying RUNNING.
    """
    resuming = self.request.retries > 0
    try:
        return run_async(execute_job, job_id, initial_state, resuming)
    except LockBusyError:
        raise self.retry(countdown=LOCK_RETRY_SECONDS, kwargs={"failures": failures})
    except SoftTimeLimitExceeded:
        run_async(mark_job_failed, job_id)
        raise
    except Exception as exc:  # noqa: BLE001
        if failures >= FAILURE_MAX_RETRIES:
            log.error("remediation.gave_up", job_id=job_id, error=str(exc))
            run_async(mark_job_failed, job_id)
            raise
        raise self.retry(exc=exc, countdown=min(2**failures * 30, 3600), kwargs={"failures": failures + 1})
