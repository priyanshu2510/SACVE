"""Matcher against real PostgreSQL: impacts, job policy, caps, filters and repo sync."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from src.core.config import Settings
from src.core.database import session_scope
from src.models.audit import AuditEvent
from src.models.cve import CVE, CVEAffectedPackage
from src.models.job import CVERepoImpact, JobStatus, RemediationJob, Repo
from src.models.sbom import SBOM
from src.services.github.repos import RepoInfo, sync_repos
from src.services.matcher.repo_filter import RepoFilter, load_repo_filter, save_override
from src.services.matcher.vulnerability_matcher import VulnerabilityMatcher

pytestmark = pytest.mark.db


def sbom_doc(*components: tuple[str, str, str, str]) -> dict:
    """(purl-type, name, version, path) -> minimal Syft-shaped CycloneDX document."""
    return {"components": [
        {"type": "library", "purl": f"pkg:{t}/{n}@{v}", "properties": [{"name": "syft:location:0:path", "value": "/" + p}]}
        for t, n, v, p in components
    ]}  # fmt: skip


async def seed_cve(cve_id, score, severity, eco, name, ranges, fixed, kev=False):
    async with session_scope() as s:
        s.add(CVE(cve_id=cve_id, source="NVD", cvss_v3_score=score, severity=severity, cisa_kev=kev, raw_data={},
                  published_at=datetime(2024, 1, 1, tzinfo=timezone.utc), description="d"))  # fmt: skip
        await s.flush()
        s.add(CVEAffectedPackage(cve_id=cve_id, ecosystem=eco, package_name=name, affected_versions=ranges, fixed_version=fixed))


async def seed_repo(name, doc=None, archived=False, topics=()):
    rid = uuid.uuid4()
    async with session_scope() as s:
        s.add(Repo(id=rid, full_name=name, archived=archived, topics=list(topics)))
        await s.flush()
        if doc is not None:
            s.add(SBOM(repo_id=rid, commit_sha="sha", document=doc))
    return rid


async def seed_standard():
    await seed_cve("CVE-2024-35195", 5.6, "MEDIUM", "pip", "requests", ["< 2.32.0"], "2.32.0")
    await seed_cve("CVE-2024-21626", 8.6, "HIGH", "go", "github.com/opencontainers/runc", ["< 1.1.12"], "1.1.12")
    await seed_cve("CVE-2020-0001", 3.0, "LOW", "pip", "requests", ["< 9.9.9"], "9.9.9")  # below threshold: ignored
    return await seed_repo("org/api", sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt"), ("golang", "github.com/opencontainers/runc", "v1.1.5", "go.mod")))


class Queue:
    def __init__(self):
        self.items = []

    def __call__(self, job_id, state):
        self.items.append((job_id, state))


def matcher(q, now=None, **cfg):
    """``now=None`` uses the real clock (job timestamps come from the database clock)."""
    return VulnerabilityMatcher(q, Settings(_env_file=None, **cfg), now=(lambda: now) if now else None)


async def count(model):
    async with session_scope() as s:
        return (await s.execute(select(func.count()).select_from(model))).scalar_one()


async def job_for(cve_id):
    async with session_scope() as s:
        return (await s.execute(select(RemediationJob).where(RemediationJob.cve_id == cve_id))).scalar_one()


async def test_creates_impacts_jobs_events_and_enqueues_in_priority_order(migrated_db):
    await seed_standard()
    q = Queue()
    summary = await matcher(q).run()
    assert (summary.cves, summary.repos, summary.impacts, summary.created, summary.enqueued) == (2, 1, 2, 2, 2)
    assert [s["cve_id"] for _, s in q.items] == ["CVE-2024-21626", "CVE-2024-35195"]  # CVSS 8.6 before 5.6

    job_id, state = q.items[1]
    assert state == {
        "job_id": job_id, "run_id": state["run_id"], "cve_id": "CVE-2024-35195", "repo_name": "org/api", "ecosystem": "pip",
        "affected_package": "requests", "installed_version": "2.31.0", "target_version": "2.32.0",
        "manifest_file_path": "requirements.txt", "cvss_score": 5.6, "severity": "MEDIUM",
    }  # fmt: skip
    assert len(state["run_id"]) == 32
    job = await job_for("CVE-2024-35195")
    assert job.status == JobStatus.QUEUED and str(job.job_id) == job_id and job.langgraph_thread_id == job.job_id
    async with session_scope() as s:
        events = [(e.event_type, e.job_id) for e in (await s.execute(select(AuditEvent).where(AuditEvent.cve_id == "CVE-2024-35195"))).scalars()]
        impacts = (await s.execute(select(CVERepoImpact))).scalars().all()
    assert sorted(t for t, _ in events) == ["JOB_QUEUED", "REPO_MATCHED"] and all(j == job.job_id for _, j in events)
    assert {(i.cve_id, i.safe_version, i.manifest_file_path) for i in impacts} == {
        ("CVE-2024-35195", "2.32.0", "requirements.txt"), ("CVE-2024-21626", "1.1.12", "go.mod")}  # fmt: skip


async def test_second_run_is_idempotent(migrated_db):
    await seed_standard()
    await matcher(Queue()).run()
    q = Queue()
    summary = await matcher(q).run()
    assert q.items == [] and summary.created == 0 and summary.skipped["in_flight"] == 2
    assert await count(RemediationJob) == 2 and await count(CVERepoImpact) == 2  # no duplicates


@pytest.mark.parametrize("status", [JobStatus.MERGED, JobStatus.BLOCKED, JobStatus.NOT_REACHABLE, JobStatus.PR_RAISED])
async def test_finished_or_in_flight_jobs_are_not_requeued(migrated_db, status):
    await seed_standard()
    await matcher(Queue()).run()
    async with session_scope() as s:
        (await s.execute(select(RemediationJob).where(RemediationJob.cve_id == "CVE-2024-35195"))).scalar_one().status = status
    q = Queue()
    await matcher(q, now=datetime.now(timezone.utc) + timedelta(days=30)).run()
    assert "CVE-2024-35195" not in [s["cve_id"] for _, s in q.items]


async def test_failed_job_is_retried_only_after_the_cool_down(migrated_db):
    await seed_standard()
    await matcher(Queue()).run()
    first = await job_for("CVE-2024-35195")
    async with session_scope() as s:
        (await s.get(RemediationJob, first.job_id)).status = JobStatus.FAILED
        (await s.execute(select(RemediationJob).where(RemediationJob.cve_id == "CVE-2024-21626"))).scalar_one().status = JobStatus.MERGED
    q = Queue()
    summary = await matcher(q, now=datetime.now(timezone.utc) + timedelta(hours=1)).run()
    assert summary.skipped["failed_recently"] == 1 and not any(s["cve_id"] == "CVE-2024-35195" for _, s in q.items)

    q = Queue()
    summary = await matcher(q, now=datetime.now(timezone.utc) + timedelta(hours=25)).run()
    (job_id, state), = [(j, s) for j, s in q.items if s["cve_id"] == "CVE-2024-35195"]
    assert summary.requeued == 1 and job_id == str(first.job_id)  # same job, same pair: no second row
    assert (await job_for("CVE-2024-35195")).status == JobStatus.QUEUED and await count(RemediationJob) == 2


async def test_per_run_cap_keeps_the_most_urgent_jobs(migrated_db):
    await seed_standard()
    q = Queue()
    summary = await matcher(q, MAX_NEW_JOBS_PER_RUN=1).run()
    assert summary.created == 1 and summary.capped == 1 and [s["cve_id"] for _, s in q.items] == ["CVE-2024-21626"]
    assert await count(RemediationJob) == 1
    q = Queue()
    await matcher(q, MAX_NEW_JOBS_PER_RUN=1).run()  # the deferred one is picked up on the next run
    assert [s["cve_id"] for _, s in q.items] == ["CVE-2024-35195"]


async def test_repo_filter_scope(migrated_db):
    await seed_cve("CVE-2024-35195", 5.6, "MEDIUM", "pip", "requests", ["< 2.32.0"], "2.32.0")
    doc = sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt"))
    await seed_repo("org/ok", doc)
    await seed_repo("org/archived", doc, archived=True)
    await seed_repo("org/exempt", doc, topics=["CVE-Exempt"])
    await seed_repo("org/blocked", doc)
    await seed_repo("org/no-sbom")
    q = Queue()
    summary = await matcher(q, REPO_BLOCKLIST="blocked").run()
    assert [s["repo_name"] for _, s in q.items] == ["org/ok"] and summary.repos == 2  # ok + no-sbom are in scope


async def test_runtime_override_replaces_static_lists(migrated_db):
    async with session_scope() as s:
        await save_override(s, ["only-this"], [])
    async with session_scope() as s:
        f = await load_repo_filter(s, Settings(_env_file=None, REPO_BLOCKLIST="x"))
    assert f == RepoFilter.from_lists(["only-this"], [])
    async with session_scope() as s:
        await save_override(s, [], ["bad"])  # second save updates in place
    async with session_scope() as s:
        assert (await load_repo_filter(s)).allows("o/anything") and not (await load_repo_filter(s)).allows("o/bad")


async def test_kev_cve_below_threshold_still_gets_a_job(migrated_db):
    await seed_cve("CVE-2024-0001", 2.0, "LOW", "pip", "requests", ["< 2.32.0"], "2.32.0", kev=True)
    await seed_repo("org/api", sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt")))
    q = Queue()
    await matcher(q).run()
    assert [s["cve_id"] for _, s in q.items] == ["CVE-2024-0001"]


async def test_affected_without_fix_is_counted_not_queued(migrated_db):
    await seed_cve("CVE-2024-0002", 9.0, "CRITICAL", "pip", "requests", ["all versions"], None)
    await seed_repo("org/api", sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt")))
    q = Queue()
    summary = await matcher(q).run()
    assert q.items == [] and summary.no_fix == 1 and summary.impacts == 0


async def test_stale_impacts_are_removed_when_the_repo_is_fixed(migrated_db):
    await seed_standard()
    rid = await seed_repo("org/other", sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt")))
    await matcher(Queue()).run()
    assert await count(CVERepoImpact) == 3
    async with session_scope() as s:  # someone bumped requests in org/other; a newer SBOM shows 2.32.0
        s.add(SBOM(repo_id=rid, commit_sha="new", document=sbom_doc(("pypi", "requests", "2.32.0", "requirements.txt")),
                   generated_at=datetime.now(timezone.utc) + timedelta(minutes=1)))  # fmt: skip
    summary = await matcher(Queue()).run()
    assert summary.stale_impacts_removed == 1 and await count(CVERepoImpact) == 2


async def test_narrowed_runs_do_not_remove_other_impacts(migrated_db):
    await seed_standard()
    await matcher(Queue()).run()
    summary = await matcher(Queue()).run(cve_ids=["CVE-2024-35195"], repo_names=["org/api"])
    assert summary.cves == 1 and summary.stale_impacts_removed == 0 and await count(CVERepoImpact) == 2


async def test_one_job_per_cve_and_repo_even_with_two_manifests(migrated_db):
    await seed_cve("CVE-2024-35195", 5.6, "MEDIUM", "pip", "requests", ["< 2.32.0"], "2.32.0")
    await seed_repo("org/api", sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt"), ("pypi", "requests", "2.30.0", "svc/requirements.txt")))
    q = Queue()
    summary = await matcher(q).run()
    assert len(q.items) == 1 and summary.skipped["duplicate_pair"] == 1


async def test_newest_sbom_wins(migrated_db):
    await seed_cve("CVE-2024-35195", 5.6, "MEDIUM", "pip", "requests", ["< 2.32.0"], "2.32.0")
    rid = await seed_repo("org/api", sbom_doc(("pypi", "requests", "2.30.0", "requirements.txt")))
    async with session_scope() as s:
        s.add(SBOM(repo_id=rid, commit_sha="n", document=sbom_doc(("pypi", "requests", "2.31.5", "requirements.txt")),
                   generated_at=datetime.now(timezone.utc) + timedelta(minutes=5)))  # fmt: skip
    q = Queue()
    await matcher(q).run()
    assert q.items[0][1]["installed_version"] == "2.31.5"


async def test_enqueue_failure_leaves_a_queued_job_that_is_recovered_later(migrated_db):
    await seed_standard()

    def broken(job_id, state):
        raise ConnectionError("broker down")

    summary = await matcher(broken).run()
    assert summary.created == 2 and summary.enqueued == 0  # jobs exist, messages were lost
    q = Queue()
    await matcher(q, now=datetime.now(timezone.utc) + timedelta(hours=7)).run()  # stale-queue rule re-sends them
    assert len(q.items) == 2


async def test_sync_repos_upserts_and_never_deletes(migrated_db):
    async with session_scope() as s:
        out = await sync_repos(s, [RepoInfo("org/a", "main", "Python", False, ["x"]), RepoInfo("org/b", "dev", None, True, [])])
    assert out == {"created": 2, "updated": 0, "total": 2}
    async with session_scope() as s:
        out = await sync_repos(s, [RepoInfo("ORG/A", "trunk", "Python", False, ["x"])])  # renamed branch; case-insensitive match
    assert out == {"created": 0, "updated": 1, "total": 1}
    async with session_scope() as s:
        rows = {r.full_name: r for r in (await s.execute(select(Repo))).scalars()}
    assert set(rows) == {"org/a", "org/b"} and rows["org/a"].default_branch == "trunk" and rows["org/b"].archived is True
