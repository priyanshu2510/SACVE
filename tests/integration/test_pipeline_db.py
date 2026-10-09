"""Pipeline services against real PostgreSQL with mocked NVD / OSV / GitHub."""

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from src.agent.deps import override_deps
from src.core.config import Settings
from src.core.database import session_scope
from src.models.audit import AuditEvent
from src.models.cve import CVE
from src.models.job import JobStatus, RemediationJob, Repo
from src.models.sbom import SBOM
from src.models.sync import SyncState
from src.services import pipeline
from src.services.cve_aggregator.nvd import NVDClient
from src.services.cve_aggregator.osv import OSVClient
from src.services.github.repos import RepoInfo
from src.services.notifications.dispatcher import NotificationDispatcher
from src.services.sbom.generator import GeneratedSBOM, parse_cyclonedx
from src.utils import retry as retry_mod
from src.utils.rate_limiter import RateLimiter
from tests.fakes import MemoryIdempotency, MemoryNotificationLog, RecordingHandler
from tests.integration.test_matcher_db import sbom_doc, seed_cve, seed_repo

pytestmark = pytest.mark.db
NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def nvd_vuln(cve_id, score=7.5):
    return {"cve": {"id": cve_id, "published": "2024-01-01T00:00:00.000", "descriptions": [{"lang": "en", "value": f"{cve_id} text."}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/x"}}]}}}  # fmt: skip


def osv_record(cve_id, ecosystem="PyPI", name="requests"):
    return {"id": cve_id, "aliases": [], "summary": "s", "affected": [
        {"package": {"ecosystem": ecosystem, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]}  # fmt: skip


class Feeds:
    """Scriptable NVD + OSV transports that record what was requested."""

    def __init__(self, vulns, osv=None, osv_fail=()):
        self.vulns = {v["cve"]["id"]: v for v in vulns}
        self.osv = osv or {}
        self.osv_fail = set(osv_fail)
        self.nvd_requests: list[dict] = []

    def nvd_handler(self, request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        self.nvd_requests.append(params)
        if "cveId" in params:
            v = self.vulns.get(params["cveId"])
            return httpx.Response(200, json={"vulnerabilities": [v] if v else [], "totalResults": 1 if v else 0})
        items = list(self.vulns.values())
        start = int(params["startIndex"])
        page = items[start : start + 10]
        return httpx.Response(200, json={"startIndex": start, "resultsPerPage": len(page), "totalResults": len(items), "vulnerabilities": page})

    def osv_handler(self, request: httpx.Request) -> httpx.Response:
        cve_id = request.url.path.rsplit("/", 1)[-1]
        if cve_id in self.osv_fail:
            return httpx.Response(500)
        return httpx.Response(200, json=self.osv[cve_id]) if cve_id in self.osv else httpx.Response(404)

    def clients(self):
        cfg = Settings(_env_file=None)
        nvd = NVDClient(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(self.nvd_handler)), rate_limiter=RateLimiter(10_000, 1))
        osv = OSVClient(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(self.osv_handler)))
        return nvd, osv


async def stored_ids():
    async with session_scope() as s:
        return sorted((await s.execute(select(CVE.cve_id))).scalars())


async def cursor():
    async with session_scope() as s:
        row = await s.get(SyncState, pipeline.CVE_CURSOR)
        return dict(row.value) if row else None


# ------------------------------------------------------------------ CVE sync
async def test_sync_stores_only_cves_with_supported_packages_and_saves_the_cursor(migrated_db):
    feeds = Feeds(
        [nvd_vuln("CVE-2024-0001"), nvd_vuln("CVE-2024-0002"), nvd_vuln("CVE-2024-0003")],
        osv={"CVE-2024-0001": osv_record("CVE-2024-0001"), "CVE-2024-0003": osv_record("CVE-2024-0003", "crates.io", "serde")},
    )  # 0002 has no OSV data; 0003 is in an unsupported ecosystem
    nvd, osv = feeds.clients()
    assert await pipeline.sync_cves(nvd, osv, now=NOW) == ["CVE-2024-0001"]
    assert await stored_ids() == ["CVE-2024-0001"]
    assert (await cursor())["last_success"] == NOW.isoformat() and (await cursor())["retry_ids"] == []
    first = feeds.nvd_requests[0]
    assert datetime.strptime(first["lastModEndDate"], "%Y-%m-%dT%H:%M:%S.000") == NOW.replace(tzinfo=None, microsecond=0)
    assert datetime.strptime(first["lastModStartDate"], "%Y-%m-%dT%H:%M:%S.000") == (NOW - timedelta(hours=24)).replace(tzinfo=None, microsecond=0)


async def test_next_run_starts_at_the_cursor_with_an_overlap(migrated_db):
    feeds = Feeds([])
    nvd, osv = feeds.clients()
    await pipeline.sync_cves(nvd, osv, now=NOW)
    later = NOW + timedelta(hours=24)
    await pipeline.sync_cves(nvd, osv, now=later)
    start = datetime.strptime(feeds.nvd_requests[-1]["lastModStartDate"], "%Y-%m-%dT%H:%M:%S.000")
    assert start == (NOW - pipeline.OVERLAP).replace(tzinfo=None, microsecond=0)
    assert (await cursor())["last_success"] == later.isoformat()


async def test_failed_cves_are_retried_on_the_next_run(migrated_db):
    feeds = Feeds([nvd_vuln("CVE-2024-0001"), nvd_vuln("CVE-2024-0002")],
                  osv={"CVE-2024-0001": osv_record("CVE-2024-0001"), "CVE-2024-0002": osv_record("CVE-2024-0002")}, osv_fail={"CVE-2024-0002"})  # fmt: skip
    nvd, osv = feeds.clients()
    assert await pipeline.sync_cves(nvd, osv, now=NOW) == ["CVE-2024-0001"]
    assert (await cursor())["retry_ids"] == ["CVE-2024-0002"]  # cursor advanced, the failure is remembered

    feeds.osv_fail.clear()
    feeds.vulns = {"CVE-2024-0002": feeds.vulns["CVE-2024-0002"]}  # the window itself no longer lists it
    nvd, osv = feeds.clients()
    ids = await pipeline.sync_cves(nvd, osv, now=NOW + timedelta(hours=1))
    assert "CVE-2024-0002" in ids and await stored_ids() == ["CVE-2024-0001", "CVE-2024-0002"]
    assert (await cursor())["retry_ids"] == []


async def test_explicit_window_does_not_touch_the_cursor(migrated_db):
    feeds = Feeds([nvd_vuln("CVE-2024-0001")], osv={"CVE-2024-0001": osv_record("CVE-2024-0001")})
    nvd, osv = feeds.clients()
    ids = await pipeline.sync_cves(nvd, osv, window=(NOW - timedelta(days=2), NOW))
    assert ids == ["CVE-2024-0001"] and await cursor() is None


async def test_many_cves_across_pages(migrated_db):
    ids = [f"CVE-2024-{i:04d}" for i in range(1, 26)]
    feeds = Feeds([nvd_vuln(i) for i in ids], osv={i: osv_record(i) for i in ids})
    nvd, osv = feeds.clients()
    assert await pipeline.sync_cves(nvd, osv, now=NOW) == ids and await stored_ids() == ids


async def test_long_windows_are_split_for_nvd(migrated_db):
    feeds = Feeds([])
    nvd, osv = feeds.clients()
    await pipeline.sync_cves(nvd, osv, window=(NOW - timedelta(days=250), NOW))
    windows = [(r["lastModStartDate"], r["lastModEndDate"]) for r in feeds.nvd_requests]
    assert len(windows) == 3  # 119 + 119 + 12 days
    for start, end in windows:
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        assert datetime.strptime(end, fmt) - datetime.strptime(start, fmt) <= timedelta(days=120)


async def test_fetch_single_cve_stores_regardless_of_relevance(migrated_db):
    feeds = Feeds([nvd_vuln("CVE-2024-0002")])  # no OSV data -> no packages
    nvd, osv = feeds.clients()
    assert await pipeline.fetch_single_cve(nvd, osv, "CVE-2024-0002") is True
    assert await stored_ids() == ["CVE-2024-0002"]
    assert await pipeline.fetch_single_cve(nvd, osv, "CVE-2000-0000") is False


# ------------------------------------------------------------------ repos / SBOM / match
class Lister:
    async def list_repos(self, org):
        return [RepoInfo("org/api", topics=[]), RepoInfo("org/old", archived=True), RepoInfo("org/exempt", topics=["cve-exempt"]),
                RepoInfo("org/blocked"), RepoInfo("org/web", "dev", "TypeScript")]  # fmt: skip


async def test_refresh_repos_syncs_everything_but_returns_only_in_scope(migrated_db, monkeypatch):
    monkeypatch.setattr(pipeline.settings, "REPO_BLOCKLIST", ["blocked"])
    assert await pipeline.refresh_repos(Lister()) == ["org/api", "org/web"]
    async with session_scope() as s:
        assert {r.full_name for r in (await s.execute(select(Repo))).scalars()} == {"org/api", "org/old", "org/exempt", "org/blocked", "org/web"}


class FakeGenerator:
    def __init__(self):
        self.calls = []

    async def generate(self, repo_name):
        self.calls.append(repo_name)
        doc = sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt"))
        return GeneratedSBOM(repo_name, "sha1", doc, f"{repo_name}/sha1.cdx.json", parse_cyclonedx(doc))


async def test_generate_sbom_for_saves_a_row_per_run(migrated_db):
    rid = await seed_repo("org/api")
    gen = FakeGenerator()
    assert await pipeline.generate_sbom_for("org/api", gen) == 1
    assert await pipeline.generate_sbom_for("org/api", gen) == 1
    async with session_scope() as s:
        rows = (await s.execute(select(SBOM).where(SBOM.repo_id == rid))).scalars().all()
    assert len(rows) == 2 and rows[0].s3_key == "org/api/sha1.cdx.json"  # history is kept


async def test_generate_sbom_for_unknown_repo(migrated_db):
    with pytest.raises(LookupError):
        await pipeline.generate_sbom_for("org/ghost", FakeGenerator())


async def test_match_respects_the_kill_switch(migrated_db, monkeypatch):
    await seed_cve("CVE-2024-35195", 5.6, "MEDIUM", "pip", "requests", ["< 2.32.0"], "2.32.0")
    await seed_repo("org/api", sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt")))
    sent = []
    monkeypatch.setattr(pipeline.settings, "AUTOMATION_ENABLED", False)
    assert await pipeline.match(lambda j, s: sent.append(j)) is None and sent == []
    monkeypatch.setattr(pipeline.settings, "AUTOMATION_ENABLED", True)
    summary = await pipeline.match(lambda j, s: sent.append(j))
    assert summary.created == 1 and len(sent) == 1


# ------------------------------------------------------------------ SLA escalation
async def make_job(cve_id, severity, status, age_hours, name="org/api"):
    async with session_scope() as s:
        cve = await s.get(CVE, cve_id)
        if cve is None:
            s.add(CVE(cve_id=cve_id, source="NVD", cvss_v3_score=9.8 if severity == "CRITICAL" else 5.0, severity=severity, raw_data={}))
            await s.flush()
        repo = (await s.execute(select(Repo).where(Repo.full_name == name))).scalar_one_or_none()
        if repo is None:
            repo = Repo(full_name=name)
            s.add(repo)
            await s.flush()
        job = RemediationJob(job_id=uuid.uuid4(), cve_id=cve_id, repo_id=repo.id, repo_name=name, status=status, affected_package="requests",
                             installed_version="2.31.0", target_version="2.32.0", manifest_file="requirements.txt",
                             created_at=datetime.now(timezone.utc) - timedelta(hours=age_hours))  # fmt: skip
        s.add(job)
        return str(job.job_id)


def dispatcher():
    handler = RecordingHandler("pagerduty")
    return handler, NotificationDispatcher([handler], MemoryIdempotency(), MemoryNotificationLog())


async def test_only_old_unresolved_critical_jobs_escalate(migrated_db):
    breached = await make_job("CVE-2024-1001", "CRITICAL", JobStatus.FAILED, 30)
    blocked = await make_job("CVE-2024-1002", "CRITICAL", JobStatus.BLOCKED, 48)
    await make_job("CVE-2024-1003", "CRITICAL", JobStatus.QUEUED, 2)  # too young
    await make_job("CVE-2024-1004", "CRITICAL", JobStatus.PR_RAISED, 99)  # has a PR
    await make_job("CVE-2024-1005", "CRITICAL", JobStatus.MERGED, 99)
    await make_job("CVE-2024-1006", "HIGH", JobStatus.FAILED, 99)  # not critical
    handler, disp = dispatcher()
    with override_deps(dispatcher=disp):
        assert sorted(await pipeline.escalate_sla()) == sorted([breached, blocked])
    assert {n.cve_id for n in handler.sent} == {"CVE-2024-1001", "CVE-2024-1002"}
    note = next(n for n in handler.sent if n.cve_id == "CVE-2024-1001")
    assert note.event == "ESCALATED" and note.metadata["cvss"] == 9.8 and "30h" in note.subject
    async with session_scope() as s:
        events = (await s.execute(select(AuditEvent).where(AuditEvent.event_type == "ESCALATED"))).scalars().all()
    assert len(events) == 2 and events[0].payload["channels"] == [{"channel": "pagerduty", "status": "sent"}]


async def test_a_job_is_escalated_only_once(migrated_db):
    await make_job("CVE-2024-1001", "CRITICAL", JobStatus.FAILED, 30)
    handler, disp = dispatcher()
    with override_deps(dispatcher=disp):
        assert len(await pipeline.escalate_sla()) == 1
        assert await pipeline.escalate_sla() == []
    assert len(handler.sent) == 1
