import pytest

from src.agent.deps import override_deps
from src.agent.nodes.audit_writer import write_audit
from src.agent.nodes.notifier import build_notification, notify_owners
from src.agent.state import TestResult
from src.services.audit.store import job_status_for
from src.services.notifications import base as notif_base
from src.models.job import JobStatus
from src.services.notifications.dispatcher import NotificationDispatcher
from tests.fakes import MemoryAuditStore, MemoryIdempotency, MemoryNotificationLog, RecordingHandler


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    from src.utils import retry as retry_mod

    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def raised(make_state, **kw):
    base = dict(job_id="job-1", terminal_status="PR_RAISED", pr_url="https://github.com/org/api-gateway/pull/7", pr_number=7,
                confidence_score=90, code_owners=["@alice", "bob@corp.com", "@org/platform"])  # fmt: skip
    return make_state(**(base | kw))


def dispatcher(*handlers):
    return NotificationDispatcher(list(handlers), MemoryIdempotency(), MemoryNotificationLog())


def test_notification_content(make_state, monkeypatch):
    monkeypatch.setattr(notif_base.settings, "OWNER_EMAIL_DOMAIN", "corp.com")
    n = build_notification(raised(make_state))
    assert n.event == "PR_RAISED" and n.subject == "CVE fix ready for review: CVE-2024-35195 in api-gateway"
    assert n.recipients == ["alice@corp.com", "bob@corp.com", "@org/platform"]
    assert "https://github.com/org/api-gateway/pull/7" in n.body and "90/100" in n.body
    assert n.metadata["pr_url"].endswith("/pull/7") and n.metadata["cvss"] == 5.6


async def test_notify_records_a_result_and_event_per_channel(make_state):
    teams, hook = RecordingHandler("teams"), RecordingHandler("webhook")
    with override_deps(dispatcher=dispatcher(teams, hook)):
        out = await notify_owners(raised(make_state))
    assert [r["status"] for r in out["notification_results"]] == ["sent", "sent"]
    assert [e["event_type"] for e in out["audit_events"]] == ["NOTIFICATION_SENT"] * 2
    assert "terminal_status" not in out  # a raised PR stays raised


async def test_notify_failure_is_recorded_not_raised(make_state):
    with override_deps(dispatcher=dispatcher(RecordingHandler("teams", fail_times=99))):
        out = await notify_owners(raised(make_state))
    assert out["notification_results"][0]["status"] == "failed" and "terminal_status" not in out and "error" not in out


async def test_notify_survives_even_a_broken_dispatcher(make_state):
    class Broken:
        async def dispatch(self, n):
            raise RuntimeError("kaboom")

    with override_deps(dispatcher=Broken()):
        out = await notify_owners(raised(make_state))
    assert out["notification_results"][0]["error"] == "kaboom" and "error" not in out


async def test_notify_with_no_applicable_channel(make_state):
    with override_deps(dispatcher=dispatcher(RecordingHandler("teams", needs_recipients=True))):
        out = await notify_owners(raised(make_state, code_owners=[]))
    assert out["notification_results"] == [] and out["audit_events"][-1]["payload"]["status"] == "skipped"


# ------------------------------------------------------------------ write_audit
@pytest.mark.parametrize(
    "terminal,status",
    [("PR_RAISED", JobStatus.PR_RAISED), ("PR_EXISTS", JobStatus.PR_RAISED), ("BLOCKED", JobStatus.BLOCKED),
     ("BASELINE_FAILING", JobStatus.BLOCKED), ("NO_TESTS", JobStatus.BLOCKED), ("NOT_REACHABLE", JobStatus.NOT_REACHABLE),
     ("FAILED", JobStatus.FAILED), ("DISABLED", JobStatus.CANCELLED), (None, JobStatus.FAILED), ("???", JobStatus.FAILED)],
)  # fmt: skip
def test_status_mapping(terminal, status):
    assert job_status_for(terminal) == status


async def test_write_audit_flushes_events_and_summary(make_state):
    store, hooked = MemoryAuditStore(), []

    async def hook(job_id):
        hooked.append(job_id)

    state = raised(
        make_state, fix_attempt=2, llm_explanation="Bump.", confidence_breakdown={"tests": 25},
        pre_fix_tests=TestResult(total=4, passed=4, failed=0, skipped=0, stdout="x" * 5000),
        audit_events=[{"event_type": "FIX_GENERATED", "payload": {"note": "token=abcdef1234567890"}, "ts": "2026-10-09T00:00:00+00:00"}],
    )  # fmt: skip
    with override_deps(audit_store=store, post_audit_hook=hook):
        assert await write_audit(state) == {}
    summary, events = store.flushed["job-1"]
    assert summary.terminal_status == "PR_RAISED" and summary.pr_number == 7 and summary.attempt_count == 2
    assert len(summary.baseline_tests["stdout"]) == 2000  # large output trimmed for the job row
    assert "abcdef1234567890" not in str(events) and hooked == ["job-1"]


async def test_write_audit_is_idempotent_and_hook_runs_once(make_state):
    store, hooked = MemoryAuditStore(), []

    async def hook(job_id):
        hooked.append(job_id)

    with override_deps(audit_store=store, post_audit_hook=hook):
        await write_audit(raised(make_state))
        await write_audit(raised(make_state))
    assert len(store.flushed) == 1 and hooked == ["job-1"]


async def test_write_audit_propagates_store_failures(make_state):
    store = MemoryAuditStore()
    store.fail_times = 1
    with override_deps(audit_store=store):
        with pytest.raises(RuntimeError, match="database unavailable"):
            await write_audit(raised(make_state))


async def test_failing_post_hook_does_not_fail_the_node(make_state):
    async def hook(job_id):
        raise RuntimeError("celery down")

    with override_deps(audit_store=MemoryAuditStore(), post_audit_hook=hook):
        assert await write_audit(raised(make_state)) == {}
