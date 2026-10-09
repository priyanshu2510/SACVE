"""Detected CVEs with their match / fix status."""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import Authed, get_session
from src.models.cve import CVE
from src.models.job import CVERepoImpact, JobStatus, RemediationJob
from src.schemas.api import CVEList, CVEOut

router = APIRouter(prefix="/api/v1/cves", tags=["cves"], dependencies=Authed)

IN_PROGRESS = {JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.FIX_GENERATED, JobStatus.SANDBOX_RUNNING, JobStatus.TESTING, JobStatus.SCAN_RUNNING, JobStatus.PAUSED}


def fix_status(affected_repos: int, jobs: dict[str, int]) -> str:
    """Overall state of a CVE across the repositories it affects.

    ``no_impact`` (matches nothing), ``unaddressed`` (affects repos, no job yet), ``in_progress``, ``pr_raised``
    (PRs waiting for review), ``needs_attention`` (blocked / failed work), ``fixed`` (every affected repo merged).
    """
    if affected_repos == 0:
        return "no_impact"
    if not jobs:
        return "unaddressed"
    merged = jobs.get(JobStatus.MERGED.value, 0)
    if merged >= affected_repos and sum(jobs.values()) == merged:
        return "fixed"
    if any(JobStatus(s) in IN_PROGRESS for s in jobs):
        return "in_progress"
    if jobs.get(JobStatus.PR_RAISED.value):
        return "pr_raised"
    if sum(jobs.values()) - merged > 0:
        return "needs_attention"
    return "unaddressed"


@router.get("", response_model=CVEList)
async def list_cves(
    severity: str | None = None,
    kev: bool | None = None,
    q: str | None = Query(default=None, description="CVE id prefix, e.g. CVE-2024"),
    only_affecting: bool = Query(default=False, description="only CVEs that affect at least one repository"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> CVEList:
    """List CVEs (highest CVSS first) with how many repos they affect and the state of the jobs for them."""
    conditions = []
    if severity:
        conditions.append(CVE.severity == severity.upper())
    if kev is not None:
        conditions.append(CVE.cisa_kev == kev)
    if q:
        conditions.append(CVE.cve_id.like(q.upper().replace("%", "").replace("_", "") + "%"))
    if only_affecting:
        conditions.append(CVE.cve_id.in_(select(CVERepoImpact.cve_id)))
    total = (await session.execute(select(func.count()).select_from(CVE).where(*conditions))).scalar_one()
    cves = (
        await session.execute(
            select(CVE).where(*conditions).order_by(CVE.cisa_kev.desc(), CVE.cvss_v3_score.desc().nulls_last(), CVE.cve_id).limit(limit).offset(offset)
        )
    ).scalars().all()
    ids = [c.cve_id for c in cves]
    impacts = dict((await session.execute(select(CVERepoImpact.cve_id, func.count(func.distinct(CVERepoImpact.repo_id))).where(CVERepoImpact.cve_id.in_(ids)).group_by(CVERepoImpact.cve_id))).all()) if ids else {}
    jobs: dict[str, dict[str, int]] = defaultdict(dict)
    if ids:
        for cve_id, status, n in (await session.execute(select(RemediationJob.cve_id, RemediationJob.status, func.count()).where(RemediationJob.cve_id.in_(ids)).group_by(RemediationJob.cve_id, RemediationJob.status))).all():
            jobs[cve_id][status.value] = n
    items = [
        CVEOut(cve_id=c.cve_id, title=c.title, severity=c.severity, cvss=c.cvss_v3_score, cisa_kev=c.cisa_kev, published_at=c.published_at,
               affected_repos=impacts.get(c.cve_id, 0), jobs=jobs.get(c.cve_id, {}), fix_status=fix_status(impacts.get(c.cve_id, 0), jobs.get(c.cve_id, {})))
        for c in cves
    ]  # fmt: skip
    return CVEList(total=total, limit=limit, offset=offset, items=items)
