"""Audit-queue tasks: Confluence / JIRA synchronisation and confidence calibration."""

from __future__ import annotations

from typing import Any

from src.core.database import session_scope
from src.services import calibration
from src.services.tracking import TrackingService
from src.workers.celery_app import QUEUE_AUDIT, celery_app
from src.workers.runtime import run_async


async def _sync(job_id: str) -> None:
    await TrackingService.from_settings().sync(job_id)


async def _daily() -> str | None:
    return await TrackingService.from_settings().publish_daily_page()


async def _recalibrate() -> dict[str, Any]:
    async with session_scope() as session:
        return await calibration.recalibrate(session)


@celery_app.task(name="audit.sync_tracking", bind=True, max_retries=3, default_retry_delay=120)
def sync_tracking_task(self: Any, job_id: str) -> None:
    """After a job's audit trail is flushed: update its Confluence page and JIRA ticket."""
    try:
        run_async(_sync, job_id)
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc, countdown=min(120 * 2**self.request.retries, 1800))


@celery_app.task(name="audit.daily_run_page")
def daily_run_page_task() -> str | None:
    """07:00 UTC: publish the daily run page."""
    return run_async(_daily)


@celery_app.task(name="audit.recalibrate_confidence")
def recalibrate_confidence_task() -> dict[str, Any]:
    """Weekly: recompute confidence-tier thresholds from reviewed-PR outcomes."""
    return run_async(_recalibrate)


def enqueue_tracking_sync(job_id: str) -> None:
    """Queue a tracking sync (the default post-audit hook)."""
    sync_tracking_task.apply_async(args=[job_id], queue=QUEUE_AUDIT)
