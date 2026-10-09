"""Human feedback: what happened to each bot PR (merged clean / merged with edits / closed unmerged)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.models.audit import AuditEvent, PROutcome, PROutcomeKind
from src.models.job import JobStatus, RemediationJob
from src.services.github.pr_description import MARKER_RE

log = structlog.get_logger(__name__)

_EVENT = {
    PROutcomeKind.MERGED_CLEAN: "PR_MERGED_CLEAN",
    PROutcomeKind.MERGED_EDITED: "PR_MERGED_EDITED",
    PROutcomeKind.CLOSED_UNMERGED: "PR_CLOSED_UNMERGED",
}


@dataclass(frozen=True)
class RecordedOutcome:
    """The result of recording a closed PR."""

    job_id: str
    cve_id: str
    repo_name: str
    kind: PROutcomeKind
    pr_url: str | None
    first_time: bool  # False for a redelivered webhook


def classify(pr: dict[str, Any]) -> PROutcomeKind:
    """``merged`` -> clean unless reviewers pushed extra commits; otherwise closed unmerged.

    The bot opens PRs with a single commit, so ``commits > 1`` means a human added to the branch.
    """
    if not pr.get("merged"):
        return PROutcomeKind.CLOSED_UNMERGED
    return PROutcomeKind.MERGED_EDITED if int(pr.get("commits", 1)) > 1 else PROutcomeKind.MERGED_CLEAN


async def record_pr_closed(session: AsyncSession, payload: dict[str, Any]) -> RecordedOutcome | None:
    """Handle a ``pull_request`` webhook with ``action=closed``. Returns ``None`` for PRs that are not ours.

    A PR is ours only if its branch has the bot prefix, its body carries our job marker, AND the job's
    recorded repo and PR number match. (A marker alone is not trusted: anyone can paste text in a PR.)
    """
    pr = payload.get("pull_request") or {}
    repo_name = (payload.get("repository") or {}).get("full_name", "")
    if not str((pr.get("head") or {}).get("ref", "")).startswith(settings.PR_BRANCH_PREFIX):
        return None
    marker = MARKER_RE.search(pr.get("body") or "")
    if marker is None:
        return None
    try:
        job_id = uuid.UUID(marker.group("job"))
    except ValueError:
        return None
    job = await session.get(RemediationJob, job_id)
    if job is None or job.repo_name.lower() != repo_name.lower() or job.pr_number != pr.get("number"):
        log.warning("pr_outcome.unmatched", job_id=str(job_id), repo=repo_name, pr=pr.get("number"))
        return None

    kind = classify(pr)
    inserted = (
        await session.execute(
            pg_insert(PROutcome)
            .values(job_id=job_id, repo_name=job.repo_name, pr_number=job.pr_number, outcome=kind.value, predicted_confidence=job.confidence_score)
            .on_conflict_do_nothing(constraint="uq_pr_outcome_job")
            .returning(PROutcome.id)
        )
    ).first()
    first_time = inserted is not None
    if first_time:
        merged = kind != PROutcomeKind.CLOSED_UNMERGED
        # a human rejecting the PR is a final answer: BLOCKED stops the matcher from raising it again
        job.status = JobStatus.MERGED if merged else JobStatus.BLOCKED
        events = [_EVENT[kind]] + (["PR_MERGED"] if merged else [])
        for event_type in events:
            session.add(AuditEvent(job_id=job_id, cve_id=job.cve_id, repo_name=job.repo_name, event_type=event_type,
                                   payload={"pr_number": job.pr_number, "predicted_confidence": job.confidence_score,
                                            "commits": pr.get("commits"), "merged_by": (pr.get("merged_by") or {}).get("login")}))  # fmt: skip
    return RecordedOutcome(str(job_id), job.cve_id, job.repo_name, kind, job.pr_url, first_time)


async def existing_outcome(session: AsyncSession, job_id: uuid.UUID) -> str | None:
    """The recorded outcome for a job, if any."""
    return (await session.execute(select(PROutcome.outcome).where(PROutcome.job_id == job_id))).scalar_one_or_none()
