"""Notification-queue tasks."""

from __future__ import annotations

from typing import Any

from src.services import pipeline
from src.workers.celery_app import celery_app
from src.workers.runtime import run_async


@celery_app.task(name="notifications.sla_escalation")
def sla_escalation_task() -> dict[str, Any]:
    """Every 2 hours: escalate CRITICAL CVEs that still have no PR after the SLA window."""
    escalated = run_async(pipeline.escalate_sla)
    return {"escalated": len(escalated), "job_ids": escalated}
