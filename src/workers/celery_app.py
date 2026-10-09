"""Celery application: Redis broker, four queues, and the beat schedule."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from celery.signals import setup_logging
from kombu import Queue

from src.core.config import settings
from src.core.logging import configure_logging

QUEUE_SCANNING = "scanning"  # CVE fetch, SBOM, matching
QUEUE_REMEDIATION = "remediation"  # LangGraph fix-agent runs
QUEUE_NOTIFICATIONS = "notifications"
QUEUE_AUDIT = "audit"

# A fix-agent run can take up to ~MAX_FIX_ATTEMPTS sandbox runs; with acks_late Redis would redeliver an
# unacknowledged message after `visibility_timeout`, which must therefore exceed the longest task.
VISIBILITY_TIMEOUT_SECONDS = 4 * 3600
REMEDIATION_SOFT_LIMIT_SECONDS = 3 * 3600
REMEDIATION_HARD_LIMIT_SECONDS = REMEDIATION_SOFT_LIMIT_SECONDS + 600

celery_app = Celery(
    "cve_remediation",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "src.workers.tasks.scan_tasks",
        "src.workers.tasks.remediation_tasks",
        "src.workers.tasks.notification_tasks",
        "src.workers.tasks.audit_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # tasks are long: do not hoard messages
    task_track_started=True,
    result_expires=7 * 24 * 3600,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": VISIBILITY_TIMEOUT_SECONDS},
    task_default_queue=QUEUE_SCANNING,
    task_queues=(Queue(QUEUE_SCANNING), Queue(QUEUE_REMEDIATION), Queue(QUEUE_NOTIFICATIONS), Queue(QUEUE_AUDIT)),
    task_routes={
        "scan.*": {"queue": QUEUE_SCANNING},
        "remediation.*": {"queue": QUEUE_REMEDIATION},
        "notifications.*": {"queue": QUEUE_NOTIFICATIONS},
        "audit.*": {"queue": QUEUE_AUDIT},
        "ops.*": {"queue": QUEUE_SCANNING},
    },
    beat_schedule={
        "cve-feed-fetch": {"task": "scan.sync_cves", "schedule": crontab(hour=6, minute=0)},  # 06:00 UTC daily
        "sbom-regeneration": {"task": "scan.regenerate_sboms", "schedule": crontab(hour=2, minute=0)},  # 02:00 UTC daily
        "sla-escalation-check": {"task": "notifications.sla_escalation", "schedule": crontab(minute=0, hour="*/2")},  # every 2 h
        "confluence-daily-page": {"task": "audit.daily_run_page", "schedule": crontab(hour=7, minute=0)},  # 07:00 UTC daily
        "confidence-recalibration": {"task": "audit.recalibrate_confidence", "schedule": crontab(hour=3, minute=0, day_of_week="mon")},
    },
)


@setup_logging.connect
def _configure_worker_logging(**_: object) -> None:
    """Use our structlog JSON configuration instead of Celery's default logging."""
    configure_logging()


@celery_app.task(name="ops.ping")
def ping() -> str:
    """Health probe used by deployment checks and the wiring smoke test."""
    return "pong"
