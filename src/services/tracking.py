"""Keeps the JIRA ticket and the Confluence audit page of each job in step with the job."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import func, select

from src.agent.deps import get_idempotency_store
from src.core.config import Settings, settings as default_settings
from src.core.database import session_scope
from src.models.audit import AuditEvent
from src.models.cve import CVE
from src.models.job import RemediationJob
from src.services.confluence.publisher import ConfluencePublisher
from src.services.jira.issue_creator import JiraIssueCreator, TicketContext
from src.services.notifications.base import resolve_recipients

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class TrackingRefs:
    """Links to the external records of a job (either may be ``None`` when not configured or failed)."""

    jira_issue_key: str | None = None
    confluence_page_url: str | None = None


def integrations_configured(cfg: Settings) -> tuple[bool, bool]:
    """``(confluence, jira)``: an integration is on only when its API token is set."""
    return bool(cfg.CONFLUENCE_API_TOKEN), bool(cfg.JIRA_API_TOKEN)


class TrackingService:
    """Best-effort bridge to Confluence and JIRA. Failures are logged and never break remediation."""

    def __init__(self, confluence: ConfluencePublisher | None, jira: JiraIssueCreator | None) -> None:
        self._confluence, self._jira = confluence, jira

    @classmethod
    def from_settings(cls, cfg: Settings | None = None) -> TrackingService:
        """Build with the integrations whose credentials are configured."""
        cfg = cfg or default_settings
        wiki, jira = integrations_configured(cfg)
        return cls(ConfluencePublisher(cfg) if wiki else None, JiraIssueCreator(cfg) if jira else None)

    # -- data ----------------------------------------------------------------------------------
    @staticmethod
    async def _load(job_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        async with session_scope() as s:
            job = await s.get(RemediationJob, uuid.UUID(job_id))
            if job is None:
                return None
            cve = await s.get(CVE, job.cve_id)
            events = (await s.execute(select(AuditEvent).where(AuditEvent.job_id == job.job_id).order_by(AuditEvent.ts, AuditEvent.id))).scalars().all()
            data = {
                "job_id": job_id, "cve_id": job.cve_id, "repo_name": job.repo_name, "status": job.status.value,
                "affected_package": job.affected_package, "installed_version": job.installed_version, "target_version": job.target_version,
                "confidence_score": job.confidence_score, "attempt_count": job.attempt_count, "pr_url": job.pr_url,
                "jira_issue_key": job.jira_issue_key, "confluence_page_url": job.confluence_page_url,
                "severity": (cve.severity if cve else None) or "MEDIUM", "cvss": cve.cvss_v3_score if cve else None,
            }  # fmt: skip
            return data, [{"ts": e.ts.isoformat(), "event_type": e.event_type, "payload": e.payload} for e in events]

    @staticmethod
    async def _save(job_id: str, **fields: Any) -> None:
        async with session_scope() as s:
            job = await s.get(RemediationJob, uuid.UUID(job_id))
            if job is not None:
                for k, v in fields.items():
                    setattr(job, k, v)

    @staticmethod
    def _context(job: dict[str, Any], events: list[dict[str, Any]]) -> TicketContext:
        owners: list[str] = []
        for e in events:
            if e["event_type"] == "PR_RAISED":
                owners = e["payload"].get("owners", [])
        emails = [o for o in resolve_recipients(owners) if "@" in o and not o.startswith("@")]
        return TicketContext(job["job_id"], job["cve_id"], job["severity"], job["cvss"], job["repo_name"], job["affected_package"],
                             job["installed_version"], job["target_version"], job["status"], job["pr_url"], job["confluence_page_url"],
                             emails, job["jira_issue_key"])  # fmt: skip

    # -- operations ----------------------------------------------------------------------------
    async def ensure(self, job_id: str) -> TrackingRefs:
        """Create the Confluence page and (Critical/High only) the JIRA ticket if they do not exist yet.

        Called before the agent runs so the PR description and notifications can link to both.
        """
        loaded = await self._load(job_id)
        if loaded is None:
            return TrackingRefs()
        job, events = loaded
        if self._confluence is not None and not job["confluence_page_url"]:
            try:
                ref = await self._confluence.publish_cve_page(job, events)
                job["confluence_page_url"] = ref.url
                await self._save(job_id, confluence_page_url=ref.url)
            except Exception as exc:  # noqa: BLE001
                log.error("tracking.confluence_failed", job_id=job_id, error=str(exc))
        if self._jira is not None and not job["jira_issue_key"] and self._jira.wants(job["severity"]):
            try:
                key = await self._jira.create_issue(self._context(job, events))
                job["jira_issue_key"] = key
                await self._save(job_id, jira_issue_key=key)
            except Exception as exc:  # noqa: BLE001
                log.error("tracking.jira_create_failed", job_id=job_id, error=str(exc))
        return TrackingRefs(job["jira_issue_key"], job["confluence_page_url"])

    async def sync(self, job_id: str) -> None:
        """After the audit flush: final Confluence page, JIRA description/assignee/comment/status."""
        await self.ensure(job_id)
        loaded = await self._load(job_id)
        if loaded is None:
            return
        job, events = loaded
        if self._confluence is not None:
            try:
                await self._confluence.publish_cve_page(job, events)
            except Exception as exc:  # noqa: BLE001
                log.error("tracking.confluence_sync_failed", job_id=job_id, error=str(exc))
        if self._jira is None or not job["jira_issue_key"]:
            return
        ctx = self._context(job, events)
        idem = get_idempotency_store()
        try:
            await self._jira.update_description(ctx.issue_key or "", ctx)
            if ctx.pr_url and await idem.get(f"jira_comment:{job_id}") is None:
                await self._jira.comment(ctx.issue_key or "", "Pull request raised for review:", ctx.pr_url)
                await idem.put(f"jira_comment:{job_id}", "jira", {"pr": ctx.pr_url})
            if ctx.owner_emails and await idem.get(f"jira_assign:{job_id}") is None:
                if await self._jira.assign(ctx.issue_key or "", ctx.owner_emails[0]):
                    await idem.put(f"jira_assign:{job_id}", "jira", {"assignee": ctx.owner_emails[0]})
            await self._jira.sync_status(ctx)
        except Exception as exc:  # noqa: BLE001
            log.error("tracking.jira_sync_failed", job_id=job_id, error=str(exc))

    async def publish_daily_page(self, now: datetime | None = None) -> str | None:
        """Daily run page covering the last 24 hours; returns its URL (``None`` if Confluence is off)."""
        if self._confluence is None:
            return None
        now = now or datetime.now(timezone.utc)
        since = now - timedelta(hours=24)
        async with session_scope() as s:
            jobs = (await s.execute(select(RemediationJob).where(RemediationJob.created_at >= since).order_by(RemediationJob.created_at))).scalars().all()
            cves = (await s.execute(select(func.count()).select_from(CVE).where(CVE.updated_at >= since))).scalar_one()
            by_status: dict[str, int] = {}
            for j in jobs:
                by_status[j.status.value] = by_status.get(j.status.value, 0) + 1
            stats = {"cves": cves, "jobs": len(jobs), "repos": len({j.repo_id for j in jobs}), "by_status": by_status}
            rows = [{"cve_id": j.cve_id, "repo_name": j.repo_name, "status": j.status.value, "pr_url": j.pr_url, "jira_issue_key": j.jira_issue_key} for j in jobs]
        return (await self._confluence.publish_daily_page(now, stats, rows)).url
