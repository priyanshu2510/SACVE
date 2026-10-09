"""Scanning-queue tasks: CVE feed, repo/SBOM refresh and CVE x SBOM matching."""

from __future__ import annotations

from typing import Any

import structlog

from src.services import pipeline
from src.services.cve_aggregator.nvd import NVDClient
from src.services.cve_aggregator.osv import OSVClient
from src.workers.celery_app import QUEUE_REMEDIATION, QUEUE_SCANNING, celery_app
from src.workers.runtime import run_async

log = structlog.get_logger(__name__)


def enqueue_fix_job(job_id: str, initial_state: dict[str, Any]) -> None:
    """Hand a job to the remediation queue (the matcher's ``enqueue`` callback)."""
    from src.workers.tasks.remediation_tasks import run_fix_agent_task

    run_fix_agent_task.apply_async(args=[job_id, initial_state], queue=QUEUE_REMEDIATION)


def _summary(summary: Any) -> dict[str, Any] | None:
    return None if summary is None else {**{k: v for k, v in vars(summary).items() if k != "skipped"}, "skipped": dict(summary.skipped)}


async def _sync_cves() -> list[str]:
    async with NVDClient() as nvd, OSVClient() as osv:
        return await pipeline.sync_cves(nvd, osv)


async def _scan_cve(cve_id: str) -> dict[str, Any]:
    async with NVDClient() as nvd, OSVClient() as osv:
        found = await pipeline.fetch_single_cve(nvd, osv, cve_id)
    if not found:
        return {"cve_id": cve_id, "found": False}
    return {"cve_id": cve_id, "found": True, "match": _summary(await pipeline.match(enqueue_fix_job, cve_ids=[cve_id]))}


@celery_app.task(name="scan.sync_cves", bind=True, max_retries=2, default_retry_delay=600)
def sync_cves_task(self: Any) -> dict[str, Any]:
    """Daily CVE feed fetch -> store relevant CVEs -> match them against all SBOMs."""
    try:
        cve_ids = run_async(_sync_cves)
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc)
    if cve_ids:
        match_cves_task.apply_async(args=[cve_ids], queue=QUEUE_SCANNING)
    return {"stored": len(cve_ids)}


@celery_app.task(name="scan.match_cves")
def match_cves_task(cve_ids: list[str]) -> dict[str, Any] | None:
    """Match specific CVEs against every repository's latest SBOM and enqueue fix jobs."""
    return _summary(run_async(pipeline.match, enqueue_fix_job, cve_ids=cve_ids))


@celery_app.task(name="scan.match_repos")
def match_repos_task(repo_names: list[str]) -> dict[str, Any] | None:
    """Match all CVEs against specific repositories (after their SBOM was refreshed)."""
    return _summary(run_async(pipeline.match, enqueue_fix_job, repo_names=repo_names))


@celery_app.task(name="scan.regenerate_sboms")
def regenerate_sboms_task(repo_names: list[str] | None = None) -> dict[str, Any]:
    """Daily: refresh the repo list, then fan out one SBOM task per in-scope repo (optionally a subset)."""
    in_scope = run_async(pipeline.refresh_repos)
    if repo_names:
        wanted = {n.lower() for n in repo_names}
        in_scope = [r for r in in_scope if r.lower() in wanted or r.split("/")[-1].lower() in wanted]
    for repo in in_scope:
        generate_sbom_task.apply_async(args=[repo], queue=QUEUE_SCANNING)
    return {"repos": len(in_scope)}


@celery_app.task(name="scan.generate_sbom", bind=True, max_retries=3, default_retry_delay=120)
def generate_sbom_task(self: Any, repo_name: str) -> dict[str, Any]:
    """Generate one repo's SBOM, then match every known CVE against it."""
    try:
        components = run_async(pipeline.generate_sbom_for, repo_name)
    except Exception as exc:  # noqa: BLE001 - transient clone/syft/S3 problems are retried
        raise self.retry(exc=exc, countdown=min(120 * 2**self.request.retries, 1800))
    match_repos_task.apply_async(args=[[repo_name]], queue=QUEUE_SCANNING)
    return {"repo": repo_name, "components": components}


@celery_app.task(name="scan.scan_cve", bind=True, max_retries=2, default_retry_delay=300)
def scan_cve_task(self: Any, cve_id: str) -> dict[str, Any]:
    """Manual: fetch one CVE and match it across all repositories."""
    try:
        return run_async(_scan_cve, cve_id)
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc)
