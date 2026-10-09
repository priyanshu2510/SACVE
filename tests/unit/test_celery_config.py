from celery.schedules import crontab

from src.workers.celery_app import (
    REMEDIATION_HARD_LIMIT_SECONDS, REMEDIATION_SOFT_LIMIT_SECONDS, VISIBILITY_TIMEOUT_SECONDS, celery_app,
)  # fmt: skip
import src.workers.tasks.notification_tasks  # noqa: F401
import src.workers.tasks.remediation_tasks  # noqa: F401
import src.workers.tasks.scan_tasks  # noqa: F401

conf = celery_app.conf


def queue_for(task_name: str) -> str:
    return celery_app.amqp.router.route({}, task_name)["queue"].name


def test_four_queues_exist():
    assert {q.name for q in conf.task_queues} == {"scanning", "remediation", "notifications", "audit"}


def test_tasks_are_routed_to_their_queue():
    assert queue_for("scan.sync_cves") == queue_for("scan.generate_sbom") == queue_for("scan.match_cves") == "scanning"
    assert queue_for("remediation.run_fix_agent") == "remediation"
    assert queue_for("notifications.sla_escalation") == "notifications"
    assert queue_for("ops.ping") == "scanning"


def test_beat_schedule_matches_the_spec():
    sched = {e["task"]: e["schedule"] for e in conf.beat_schedule.values()}
    assert sched["scan.sync_cves"] == crontab(hour=6, minute=0)  # 06:00 UTC CVE feed
    assert sched["scan.regenerate_sboms"] == crontab(hour=2, minute=0)  # 02:00 UTC SBOM regeneration
    assert sched["notifications.sla_escalation"] == crontab(minute=0, hour="*/2")  # every 2 hours
    assert conf.timezone == "UTC"
    for entry in conf.beat_schedule.values():
        assert entry["task"] in celery_app.tasks  # no schedule points at a missing task


def test_reliability_settings():
    assert conf.task_acks_late and conf.task_reject_on_worker_lost and conf.worker_prefetch_multiplier == 1
    assert conf.task_serializer == "json" and conf.accept_content == ["json"]  # never unpickle broker messages
    # with acks_late, Redis redelivers after visibility_timeout: it must exceed the longest task
    assert conf.broker_transport_options["visibility_timeout"] == VISIBILITY_TIMEOUT_SECONDS
    assert VISIBILITY_TIMEOUT_SECONDS > REMEDIATION_HARD_LIMIT_SECONDS > REMEDIATION_SOFT_LIMIT_SECONDS


def test_remediation_task_limits():
    task = celery_app.tasks["remediation.run_fix_agent"]
    assert task.acks_late and task.soft_time_limit == REMEDIATION_SOFT_LIMIT_SECONDS and task.time_limit == REMEDIATION_HARD_LIMIT_SECONDS
