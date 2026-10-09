"""Audit persistence: append-only events plus the final ``remediation_jobs`` update, in one transaction."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

import structlog

from src.core.database import session_scope
from src.models.audit import AuditEvent
from src.models.job import IdempotencyKey, JobStatus, RemediationJob

log = structlog.get_logger(__name__)

_STATUS_BY_TERMINAL = {
    "PR_RAISED": JobStatus.PR_RAISED,
    "PR_EXISTS": JobStatus.PR_RAISED,
    "BLOCKED": JobStatus.BLOCKED,
    "BASELINE_FAILING": JobStatus.BLOCKED,
    "NO_TESTS": JobStatus.BLOCKED,
    "NOT_REACHABLE": JobStatus.NOT_REACHABLE,
    "FAILED": JobStatus.FAILED,
    "DISABLED": JobStatus.CANCELLED,
}


def job_status_for(terminal_status: str | None) -> JobStatus:
    """Map the graph's terminal status to the ``remediation_jobs`` lifecycle state."""
    return _STATUS_BY_TERMINAL.get(terminal_status or "", JobStatus.FAILED)


@dataclass
class JobSummary:
    """The fields of the final state that are copied onto the job row."""

    job_id: str
    cve_id: str
    repo_name: str
    terminal_status: str | None
    run_id: str = ""
    confidence_score: int | None = None
    confidence_breakdown: dict[str, Any] | None = None
    llm_explanation: str | None = None
    breaking_change_risk: str | None = None
    baseline_tests: dict[str, Any] | None = None
    postfix_tests: dict[str, Any] | None = None
    pr_url: str | None = None
    pr_number: int | None = None
    jira_issue_key: str | None = None
    confluence_page_url: str | None = None
    attempt_count: int = 0


@runtime_checkable
class AuditStore(Protocol):
    """Flushes a job's audit trail exactly once."""

    async def flush(self, summary: JobSummary, events: list[dict[str, Any]]) -> bool:
        """Persist ``events`` and update the job. Returns ``False`` if this job was already flushed."""


def _ts(value: Any) -> datetime:
    if isinstance(value, str):
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


class DbAuditStore:
    """PostgreSQL implementation. ``job_id`` must be a UUID (as created by the matcher)."""

    async def flush(self, summary: JobSummary, events: list[dict[str, Any]]) -> bool:
        """Insert events + update the job in a single transaction, guarded by ``audit:{job_id}``."""
        job_uuid = uuid.UUID(summary.job_id)
        key = f"audit:{summary.job_id}:{summary.run_id}" if summary.run_id else f"audit:{summary.job_id}"
        async with session_scope() as session:
            if await session.get(IdempotencyKey, key) is not None:
                return False
            session.add(IdempotencyKey(key=key, scope="audit", result={"events": len(events)}))
            session.add_all(
                AuditEvent(
                    job_id=job_uuid,
                    cve_id=summary.cve_id,
                    repo_name=summary.repo_name,
                    event_type=e["event_type"],
                    payload=e.get("payload", {}),
                    ts=_ts(e.get("ts")),
                )
                for e in events
            )
            job = await session.get(RemediationJob, job_uuid)
            if job is None:
                log.warning("audit.job_row_missing", job_id=summary.job_id)
            else:
                job.status = job_status_for(summary.terminal_status)
                job.confidence_score = summary.confidence_score
                job.confidence_breakdown = summary.confidence_breakdown or {}
                job.llm_explanation = summary.llm_explanation
                job.breaking_change_risk = summary.breaking_change_risk
                job.baseline_tests = summary.baseline_tests or {}
                job.postfix_tests = summary.postfix_tests or {}
                job.pr_url, job.pr_number = summary.pr_url, summary.pr_number
                job.jira_issue_key = summary.jira_issue_key or job.jira_issue_key
                job.confluence_page_url = summary.confluence_page_url or job.confluence_page_url
                job.attempt_count = summary.attempt_count
                job.langgraph_thread_id = job_uuid
        return True
