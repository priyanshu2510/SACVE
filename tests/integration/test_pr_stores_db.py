"""Real PostgreSQL: audit flush, idempotency keys, notification log, and a full graph run on top of them."""

import uuid

import httpx
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import SecretStr
from sqlalchemy import func, select, text

from src.agent import runner
from src.agent.deps import override_deps
from src.agent.runner import run_fix_agent
from src.core.database import session_scope
from src.models.audit import AuditEvent
from src.models.cve import CVE
from src.models.job import IdempotencyKey, JobStatus, RemediationJob, Repo
from src.models.notification import NotificationLog
from src.services.audit.store import DbAuditStore, JobSummary
from src.services.idempotency import DbIdempotencyStore
from src.services.notifications.base import Notification, NotificationResult
from src.services.notifications.dispatcher import NotificationDispatcher
from src.services.notifications.log_store import DbNotificationLogStore
from src.utils import retry as retry_mod
from tests.conftest import FakeContentSource
from tests.fakes import FakePRService, FakeSandboxManager, RecordingHandler
from tests.integration.test_graph_core_run import APP, INITIAL, MANIFEST
from tests.llm_helpers import Recorder, chat, good

pytestmark = pytest.mark.db


async def seed_job(job_id: uuid.UUID) -> None:
    repo_id = uuid.uuid4()
    async with session_scope() as s:
        s.add(CVE(cve_id="CVE-2024-35195", source="NVD", raw_data={}))
        s.add(Repo(id=repo_id, full_name="org/api-gateway"))
        await s.flush()
        s.add(RemediationJob(job_id=job_id, cve_id="CVE-2024-35195", repo_id=repo_id, repo_name="org/api-gateway",
                             affected_package="requests", installed_version="2.31.0", target_version="2.32.0",
                             manifest_file="requirements.txt"))  # fmt: skip


def summary(job_id: "uuid.UUID | str", **kw) -> JobSummary:
    base = dict(job_id=str(job_id), cve_id="CVE-2024-35195", repo_name="org/api-gateway", terminal_status="PR_RAISED",
                confidence_score=90, confidence_breakdown={"tests": 25}, pr_url="https://github.com/org/api-gateway/pull/7",
                pr_number=7, attempt_count=2, llm_explanation="Bump.", breaking_change_risk="low", baseline_tests={"passed": 4})  # fmt: skip
    return JobSummary(**(base | kw))


EVENTS = [
    {"event_type": "CONTEXT_ASSEMBLED", "payload": {"a": 1}, "ts": "2026-10-09T00:00:00+00:00"},
    {"event_type": "PR_RAISED", "payload": {"url": "u"}, "ts": "2026-10-09T00:01:00+00:00"},
]


async def count(model) -> int:
    async with session_scope() as s:
        return (await s.execute(select(func.count()).select_from(model))).scalar_one()


async def test_flush_writes_events_and_updates_the_job_once(migrated_db):
    job = uuid.uuid4()
    await seed_job(job)
    store = DbAuditStore()
    assert await store.flush(summary(job), EVENTS) is True
    assert await store.flush(summary(job), EVENTS) is False  # idempotent: Celery retry / resume
    assert await count(AuditEvent) == 2

    async with session_scope() as s:
        row = await s.get(RemediationJob, job)
        events = (await s.execute(select(AuditEvent).order_by(AuditEvent.ts))).scalars().all()
    assert row.status == JobStatus.PR_RAISED and row.pr_number == 7 and row.attempt_count == 2
    assert row.confidence_score == 90 and row.baseline_tests == {"passed": 4} and row.langgraph_thread_id == job
    assert [e.event_type for e in events] == ["CONTEXT_ASSEMBLED", "PR_RAISED"] and events[0].job_id == job
    assert events[0].ts.isoformat().startswith("2026-10-09T00:00:00") and events[0].repo_name == "org/api-gateway"


async def test_flush_is_atomic_so_a_failed_attempt_can_be_retried(migrated_db):
    job = uuid.uuid4()
    await seed_job(job)
    store = DbAuditStore()
    with pytest.raises(KeyError):
        await store.flush(summary(job), [EVENTS[0], {"payload": {}}])  # second event is malformed
    assert await count(AuditEvent) == 0 and await count(IdempotencyKey) == 0  # nothing half-written
    assert await store.flush(summary(job), EVENTS) is True


async def test_flush_without_a_job_row_still_records_the_trail(migrated_db):
    assert await DbAuditStore().flush(summary(uuid.uuid4()), EVENTS) is True and await count(AuditEvent) == 2


async def test_audit_events_cannot_be_rewritten(migrated_db):
    job = uuid.uuid4()
    await DbAuditStore().flush(summary(job), EVENTS)
    async with session_scope() as s:
        with pytest.raises(Exception, match="append-only"):
            await s.execute(text("update audit_events set event_type = 'X'"))


async def test_non_uuid_job_id_is_rejected(migrated_db):
    with pytest.raises(ValueError):
        await DbAuditStore().flush(summary("job-42"), EVENTS)


async def test_idempotency_store(migrated_db):
    store = DbIdempotencyStore()
    assert await store.get("k") is None
    await store.put("k", "create_pr", {"number": 1})
    await store.put("k", "create_pr", {"number": 2})  # ignored
    assert await store.get("k") == {"number": 1}


async def test_notification_log_records_every_attempt(migrated_db):
    n = Notification("PR_RAISED", str(uuid.uuid4()), "CVE-2024-35195", "org/api", "HIGH", "s", "b", ["a@b.com"])
    log = DbNotificationLogStore()
    await log.record(n, NotificationResult("teams", "failed", error="boom"), "notify:k")
    await log.record(n, NotificationResult("teams", "failed", error="boom again"), "notify:k")  # failures carry no key
    await log.record(n, NotificationResult("teams", "sent", {"status_code": 200}), "notify:k")
    async with session_scope() as s:
        rows = (await s.execute(select(NotificationLog).order_by(NotificationLog.attempted_at))).scalars().all()
    assert [(r.status, r.idempotency_key) for r in rows] == [("failed", None), ("failed", None), ("sent", "notify:k")]
    assert rows[0].recipients == ["a@b.com"] and rows[0].error == "boom"


async def test_full_graph_with_real_stores(migrated_db, agent_deps, monkeypatch):
    monkeypatch.setattr(runner.settings, "AUTOMATION_ENABLED", True)
    monkeypatch.setattr("src.agent.nodes.fix_generator.default_settings.LLM_API_KEY", SecretStr("k"))

    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)
    job = uuid.uuid4()
    await seed_job(job)
    src = FakeContentSource(files={"requirements.txt": MANIFEST, "app/client.py": APP}, search={"requests": ["app/client.py"]})
    idem, teams = DbIdempotencyStore(), RecordingHandler("teams")
    dispatcher = NotificationDispatcher([teams], idem, DbNotificationLogStore())
    initial = INITIAL | {"job_id": str(job)}
    with agent_deps(src, llm_transport=httpx.MockTransport(Recorder(chat(good()))), pr=FakePRService()):
        with override_deps(idempotency=idem, audit_store=DbAuditStore(), dispatcher=dispatcher):
            final = await run_fix_agent(str(job), initial, checkpointer=InMemorySaver())

    assert final.terminal_status == "PR_RAISED"
    async with session_scope() as s:
        row = await s.get(RemediationJob, job)
        types = [e.event_type for e in (await s.execute(select(AuditEvent).order_by(AuditEvent.id))).scalars()]
        keys = {k for (k,) in (await s.execute(select(IdempotencyKey.key))).all()}
        logged = (await s.execute(select(NotificationLog.status))).scalars().all()
    assert row.status == JobStatus.PR_RAISED and row.pr_url == final.pr_url and row.confidence_score == 90
    assert types == [e["event_type"] for e in final.audit_events] and types[-2:] == ["PR_RAISED", "NOTIFICATION_SENT"]
    assert keys == {f"create_pr:{job}", f"notify:{job}:PR_RAISED:teams", f"audit:{job}"}
    assert logged == ["sent"]
