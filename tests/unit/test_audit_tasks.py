import src.workers.tasks.audit_tasks as at
from src.agent.deps import get_post_audit_hook
from tests.unit.test_celery_config import queue_for


def test_audit_tasks_route_to_the_audit_queue():
    assert queue_for("audit.sync_tracking") == queue_for("audit.daily_run_page") == queue_for("audit.recalibrate_confidence") == "audit"


def test_new_beat_entries():
    from celery.schedules import crontab

    from src.workers.celery_app import celery_app

    sched = {e["task"]: e["schedule"] for e in celery_app.conf.beat_schedule.values()}
    assert sched["audit.daily_run_page"] == crontab(hour=7, minute=0)  # 07:00 UTC Confluence daily page
    assert sched["audit.recalibrate_confidence"] == crontab(hour=3, minute=0, day_of_week="mon")


async def test_default_post_audit_hook_queues_a_tracking_sync(monkeypatch):
    sent = []
    monkeypatch.setattr(at.sync_tracking_task, "apply_async", lambda **kw: sent.append(kw))
    await get_post_audit_hook()("job-1")
    assert sent == [{"args": ["job-1"], "queue": "audit"}]


def test_sync_task_retries_on_failure_then_succeeds(monkeypatch):
    calls = []

    def run_async(fn, *args):
        calls.append(args)
        if len(calls) < 3:
            raise ConnectionError("jira down")

    monkeypatch.setattr(at, "run_async", run_async)
    res = at.sync_tracking_task.apply(args=["job-1"], throw=False)
    assert res.successful() and calls == [("job-1",)] * 3


def test_sync_task_gives_up_after_max_retries(monkeypatch):
    calls = []
    monkeypatch.setattr(at, "run_async", lambda fn, *a: calls.append(a) or (_ for _ in ()).throw(ConnectionError("down")))
    res = at.sync_tracking_task.apply(args=["job-1"], throw=False)
    assert res.failed() and len(calls) == 4  # first try + 3 retries
