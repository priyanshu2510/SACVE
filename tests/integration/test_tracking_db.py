"""TrackingService against real PostgreSQL with fake Confluence / JIRA."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from src.agent.deps import override_deps
from src.core.database import session_scope
from src.models.audit import AuditEvent, PROutcome
from src.models.cve import CVE
from src.models.job import JobStatus, RemediationJob, Repo
from src.services import calibration
from src.services.confluence.publisher import PageRef
from src.services.tracking import TrackingService, integrations_configured
from src.core.config import Settings
from tests.fakes import MemoryIdempotency

pytestmark = pytest.mark.db


class FakeConfluence:
    def __init__(self, fail=False):
        self.pages, self.fail, self.daily = [], fail, []

    async def publish_cve_page(self, job, events):
        if self.fail:
            raise RuntimeError("confluence down")
        self.pages.append((dict(job), list(events)))
        return PageRef("1", f"https://wiki/pages/{job['cve_id']}", "t")

    async def publish_daily_page(self, day, stats, jobs):
        self.daily.append((stats, jobs))
        return PageRef("2", "https://wiki/daily", "d")


class FakeJira:
    def __init__(self, severities=("CRITICAL", "HIGH"), fail=False):
        self.severities, self.fail = {s for s in severities}, fail
        self.created, self.descriptions, self.comments, self.assigned, self.statuses = [], [], [], [], []

    def wants(self, severity):
        return severity.upper() in self.severities

    async def create_issue(self, ctx):
        if self.fail:
            raise RuntimeError("jira down")
        self.created.append(ctx)
        return "SEC-1"

    async def update_description(self, key, ctx):
        self.descriptions.append((key, ctx))

    async def comment(self, key, text, href=None):
        self.comments.append((key, href))

    async def assign(self, key, email):
        self.assigned.append((key, email))
        return True

    async def sync_status(self, ctx):
        self.statuses.append(ctx.status)
        return True


async def make_job(severity="HIGH", status=JobStatus.QUEUED, pr_url=None, owners=None) -> str:
    async with session_scope() as s:
        s.add(CVE(cve_id="CVE-2024-35195", source="NVD", severity=severity, cvss_v3_score=7.5, raw_data={}))
        repo = Repo(full_name="org/api")
        s.add(repo)
        await s.flush()
        job = RemediationJob(job_id=uuid.uuid4(), cve_id="CVE-2024-35195", repo_id=repo.id, repo_name="org/api", status=status, affected_package="requests",
                             installed_version="2.31.0", target_version="2.32.0", manifest_file="requirements.txt", pr_url=pr_url)  # fmt: skip
        s.add(job)
        s.add(AuditEvent(job_id=job.job_id, cve_id="CVE-2024-35195", repo_name="org/api", event_type="JOB_QUEUED", payload={"run_id": "r"}))
        if owners is not None:
            s.add(AuditEvent(job_id=job.job_id, cve_id="CVE-2024-35195", repo_name="org/api", event_type="PR_RAISED", payload={"owners": owners}))
        return str(job.job_id)


async def row(job_id) -> RemediationJob:
    async with session_scope() as s:
        return await s.get(RemediationJob, uuid.UUID(job_id))


def tracking(wiki=None, jira=None):
    return TrackingService(wiki, jira)


async def test_ensure_creates_page_and_ticket_and_remembers_them(migrated_db):
    job_id, wiki, jira = await make_job("HIGH"), FakeConfluence(), FakeJira()
    refs = await tracking(wiki, jira).ensure(job_id)
    assert (refs.jira_issue_key, refs.confluence_page_url) == ("SEC-1", "https://wiki/pages/CVE-2024-35195")
    j = await row(job_id)
    assert j.jira_issue_key == "SEC-1" and j.confluence_page_url == "https://wiki/pages/CVE-2024-35195"
    assert wiki.pages[0][1][0]["event_type"] == "JOB_QUEUED"  # the page already carries the timeline so far
    assert jira.created[0].severity == "HIGH" and jira.created[0].confluence_url == "https://wiki/pages/CVE-2024-35195"

    again = await tracking(wiki, jira).ensure(job_id)  # idempotent
    assert again == refs and len(wiki.pages) == 1 and len(jira.created) == 1


async def test_medium_cves_get_a_page_but_no_ticket(migrated_db):
    job_id, wiki, jira = await make_job("MEDIUM"), FakeConfluence(), FakeJira()
    refs = await tracking(wiki, jira).ensure(job_id)
    assert refs.jira_issue_key is None and refs.confluence_page_url and jira.created == []


async def test_integration_failures_never_propagate(migrated_db):
    job_id = await make_job("HIGH")
    refs = await tracking(FakeConfluence(fail=True), FakeJira(fail=True)).ensure(job_id)
    assert refs.jira_issue_key is None and refs.confluence_page_url is None


async def test_disabled_integrations_and_unknown_jobs(migrated_db):
    job_id = await make_job("HIGH")
    assert (await tracking(None, None).ensure(job_id)).jira_issue_key is None
    assert (await tracking(FakeConfluence(), FakeJira()).ensure(str(uuid.uuid4()))).confluence_page_url is None


async def test_sync_updates_everything_after_the_pr_exists(migrated_db):
    job_id = await make_job("CRITICAL", JobStatus.PR_RAISED, "https://github.com/org/api/pull/7", owners=["@alice", "bob@co.com"])
    wiki, jira = FakeConfluence(), FakeJira()
    with override_deps(idempotency=MemoryIdempotency()):
        await tracking(wiki, jira).sync(job_id)
    assert wiki.pages[-1][0]["status"] == "PR_RAISED"
    (key, ctx), = jira.descriptions
    assert key == "SEC-1" and ctx.pr_url.endswith("/pull/7") and ctx.owner_emails == ["bob@co.com"]  # only real email addresses
    assert jira.comments == [("SEC-1", "https://github.com/org/api/pull/7")]
    assert jira.assigned == [("SEC-1", "bob@co.com")] and jira.statuses == ["PR_RAISED"]


async def test_sync_comments_and_assigns_only_once(migrated_db):
    job_id = await make_job("HIGH", JobStatus.PR_RAISED, "https://pr", owners=["bob@co.com"])
    jira = FakeJira()
    with override_deps(idempotency=MemoryIdempotency()):
        svc = tracking(FakeConfluence(), jira)
        await svc.sync(job_id)
        await svc.sync(job_id)
    assert len(jira.comments) == 1 and len(jira.assigned) == 1 and len(jira.descriptions) == 2  # description/status refresh each time


async def test_sync_survives_jira_errors(migrated_db):
    job_id = await make_job("HIGH", JobStatus.PR_RAISED, "https://pr")
    jira = FakeJira()
    with override_deps(idempotency=MemoryIdempotency()):
        svc = tracking(FakeConfluence(), jira)
        await svc.ensure(job_id)

        async def boom(*a, **k):
            raise RuntimeError("jira 500")

        jira.update_description = boom
        await svc.sync(job_id)  # must not raise


async def test_daily_page_stats(migrated_db):
    await make_job("HIGH", JobStatus.PR_RAISED, "https://pr")
    wiki = FakeConfluence()
    url = await tracking(wiki, None).publish_daily_page()
    assert url == "https://wiki/daily"
    (stats, jobs), = wiki.daily
    assert stats["jobs"] == 1 and stats["repos"] == 1 and stats["by_status"] == {"PR_RAISED": 1} and stats["cves"] == 1
    assert jobs[0]["cve_id"] == "CVE-2024-35195"
    assert await tracking(None, None).publish_daily_page() is None


def test_integrations_need_their_token():
    assert integrations_configured(Settings(_env_file=None)) == (False, False)
    assert integrations_configured(Settings(_env_file=None, CONFLUENCE_API_TOKEN="x", JIRA_API_TOKEN="y")) == (True, True)


# ------------------------------------------------------------------ calibration (DB)
async def test_recalibrate_persists_thresholds_and_load_reads_them(migrated_db):
    async with session_scope() as s:
        assert await calibration.load_thresholds(s) == (85, 70)  # nothing yet
        out = await calibration.recalibrate(s)
    assert out["calibrated"] is False and out["samples"] == 0

    import random

    rng = random.Random(3)
    async with session_scope() as s:
        for score, rate in [(95, 1.0), (90, 0.95), (80, 0.75), (70, 0.4), (60, 0.2)]:
            for _ in range(15):
                s.add(PROutcome(job_id=uuid.uuid4(), repo_name="o/r", pr_number=1, predicted_confidence=score,
                                outcome="MERGED_CLEAN" if rng.random() < rate else "MERGED_EDITED"))  # fmt: skip
    async with session_scope() as s:
        out = await calibration.recalibrate(s)
        again = await calibration.recalibrate(s)  # second run updates in place
    assert out["calibrated"] and again["samples"] == 75
    async with session_scope() as s:
        high, medium = await calibration.load_thresholds(s)
    assert (high, medium) == (out["high"], out["medium"]) and medium < high
