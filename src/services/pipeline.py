"""Async pipeline steps behind the Celery tasks (kept free of Celery so they are directly testable)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select

from src.agent.deps import get_dispatcher
from src.core.config import settings
from src.core.database import session_scope
from src.models.audit import AuditEvent
from src.models.cve import CVE
from src.models.job import JobStatus, RemediationJob, Repo
from src.models.sync import SyncState
from src.services.cve_aggregator.nvd import NVDClient
from src.services.cve_aggregator.osv import OSVClient
from src.services.cve_aggregator.service import CVEAggregator
from src.services.cve_aggregator.store import upsert_cve
from src.services.github.repos import OrgRepoLister, PyGithubRepoLister, sync_repos
from src.services.matcher.repo_filter import load_repo_filter
from src.services.matcher.vulnerability_matcher import EnqueueFn, MatchSummary, VulnerabilityMatcher
from src.services.notifications.base import Notification
from src.services.sbom.generator import SBOMGenerator, save_sbom

log = structlog.get_logger(__name__)

CVE_CURSOR = "cve_sync"
FIRST_RUN_LOOKBACK = timedelta(hours=24)
OVERLAP = timedelta(minutes=10)  # re-read a little before the cursor so a late-indexed CVE is not missed
NVD_MAX_WINDOW = timedelta(days=119)
MAX_RETRY_IDS = 500
BATCH = 10


def _relevant(record: Any) -> bool:
    """Only CVEs with a package in a supported ecosystem are worth storing."""
    return bool(record.affected_packages)


async def sync_cves(
    nvd: NVDClient, osv: OSVClient, *, now: datetime | None = None, window: tuple[datetime, datetime] | None = None
) -> list[str]:
    """Fetch CVEs modified since the cursor, store the relevant ones, and return their ids.

    The cursor only advances after the whole window was read; CVEs that failed to process are kept in
    ``retry_ids`` and tried again on the next run.
    """
    now = now or datetime.now(timezone.utc)
    async with session_scope() as s:
        state = await s.get(SyncState, CVE_CURSOR)
        previous = dict(state.value) if state else {}
    start = window[0] if window else (
        datetime.fromisoformat(previous["last_success"]) - OVERLAP if "last_success" in previous else now - FIRST_RUN_LOOKBACK
    )
    end = window[1] if window else now
    aggregator = CVEAggregator(nvd, osv)

    stored: list[str] = []
    failed: list[str] = []

    async def process(vuln: dict[str, Any]) -> None:
        cve_id = vuln.get("cve", {}).get("id", "?")
        try:
            record = await aggregator.from_nvd(vuln)
            if _relevant(record):
                async with session_scope() as s:
                    await upsert_cve(s, record)
                stored.append(record.cve_id)
        except Exception as exc:  # noqa: BLE001 - one bad CVE must not abort the sync
            log.error("cve_sync.cve_failed", cve_id=cve_id, error=str(exc))
            failed.append(cve_id)

    cursor_start = start
    while cursor_start < end:
        cursor_end = min(cursor_start + NVD_MAX_WINDOW, end)
        batch: list[dict[str, Any]] = []
        async for vuln in nvd.iter_modified(cursor_start, cursor_end):
            batch.append(vuln)
            if len(batch) >= BATCH:
                await _gather(process, batch)
                batch = []
        await _gather(process, batch)
        cursor_start = cursor_end

    # CVEs that failed last time get another chance (single fetch from NVD)
    for cve_id in previous.get("retry_ids", []):
        if cve_id in failed or cve_id in stored:
            continue
        raw = await nvd.get_cve(cve_id)
        if raw is not None:
            await process(raw)

    if not window:
        async with session_scope() as s:
            value = {"last_success": end.isoformat(), "retry_ids": sorted(set(failed))[:MAX_RETRY_IDS]}
            row = await s.get(SyncState, CVE_CURSOR)
            if row is None:
                s.add(SyncState(key=CVE_CURSOR, value=value))
            else:
                row.value = value
    log.info("cve_sync.done", stored=len(stored), failed=len(failed), start=start.isoformat(), end=end.isoformat())
    return sorted(set(stored))


async def _gather(fn: Any, items: list[Any]) -> None:
    import asyncio

    if items:
        await asyncio.gather(*(fn(i) for i in items))


async def fetch_single_cve(nvd: NVDClient, osv: OSVClient, cve_id: str) -> bool:
    """Fetch and store one CVE regardless of relevance filtering (manual scans). Returns whether it exists."""
    async with session_scope() as s:
        return await CVEAggregator(nvd, osv).fetch_and_store(s, cve_id) is not None


async def refresh_repos(lister: OrgRepoLister | None = None) -> list[str]:
    """Sync the org's repositories into the DB and return the names that are in scope for scanning."""
    lister = lister or PyGithubRepoLister()
    infos = await lister.list_repos(settings.GITHUB_ORG)
    async with session_scope() as s:
        await sync_repos(s, infos)
        repo_filter = await load_repo_filter(s)
        repos = (await s.execute(select(Repo))).scalars().all()
        return sorted(r.full_name for r in repos if repo_filter.allows(r.full_name, archived=r.archived, topics=list(r.topics or [])))


async def generate_sbom_for(repo_name: str, generator: SBOMGenerator | None = None) -> int:
    """Generate, archive and persist the SBOM for ``repo_name``; returns the component count."""
    generator = generator or SBOMGenerator()
    async with session_scope() as s:
        repo = (await s.execute(select(Repo).where(Repo.full_name == repo_name))).scalar_one_or_none()
        if repo is None:
            raise LookupError(f"unknown repository {repo_name}")
        repo_id = repo.id
    generated = await generator.generate(repo_name)
    async with session_scope() as s:
        await save_sbom(s, repo_id, generated)
    return len(generated.components)


async def match(enqueue: EnqueueFn, *, cve_ids: list[str] | None = None, repo_names: list[str] | None = None) -> MatchSummary | None:
    """Run the matcher unless the global kill-switch is off."""
    if not settings.AUTOMATION_ENABLED:
        log.warning("match.skipped", reason="AUTOMATION_ENABLED=false")
        return None
    return await VulnerabilityMatcher(enqueue).run(cve_ids=cve_ids, repo_names=repo_names)


async def escalate_sla(now: datetime | None = None) -> list[str]:
    """Escalate CRITICAL CVE jobs that still have no PR after ``SLA_ESCALATION_AFTER_HOURS``.

    Sends an ``ESCALATED`` notification (PagerDuty pages for CVSS >= 9) once per job and records an
    ``ESCALATED`` audit event. Returns the escalated job ids.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=settings.SLA_ESCALATION_AFTER_HOURS)
    no_pr = {JobStatus.PR_RAISED, JobStatus.MERGED, JobStatus.NOT_REACHABLE, JobStatus.CANCELLED}
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(RemediationJob, CVE)
                .join(CVE, CVE.cve_id == RemediationJob.cve_id)
                .where(CVE.severity == "CRITICAL", RemediationJob.created_at < cutoff, RemediationJob.status.notin_(no_pr))
            )
        ).all()
        already = set(
            (await s.execute(select(AuditEvent.job_id).where(AuditEvent.event_type == "ESCALATED"))).scalars()
        )
    dispatcher = get_dispatcher()
    escalated: list[str] = []
    for job, cve in rows:
        if job.job_id in already:
            continue
        hours = int((now - job.created_at).total_seconds() // 3600)
        note = Notification(
            event="ESCALATED", job_id=str(job.job_id), cve_id=job.cve_id, repo_name=job.repo_name, severity="CRITICAL",
            subject=f"SLA breach: {job.cve_id} in {job.repo_name.split('/')[-1]} has no PR after {hours}h",
            body=f"Critical CVE {job.cve_id} (CVSS {cve.cvss_v3_score}) in {job.repo_name} has no pull request after {hours} hours "
                 f"(job status: {job.status.value}).",
            metadata={"cvss": cve.cvss_v3_score or 0.0, "status": job.status.value, "hours_open": hours},
        )  # fmt: skip
        results = await dispatcher.dispatch(note)
        async with session_scope() as s:
            s.add(AuditEvent(job_id=job.job_id, cve_id=job.cve_id, repo_name=job.repo_name, event_type="ESCALATED",
                             payload={"hours_open": hours, "channels": [{"channel": r.channel, "status": r.status} for r in results]}))  # fmt: skip
        escalated.append(str(job.job_id))
    log.info("sla.escalation_done", escalated=len(escalated))
    return escalated
