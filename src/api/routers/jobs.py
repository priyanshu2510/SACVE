"""Jobs: list, detail, cancel, pause, resume and the LangGraph trace."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import Authed, GraphFactory, get_graph_factory, get_queue, get_session
from src.core.config import settings
from src.core.database import session_scope
from src.core.redaction import redact_text
from src.models.audit import AuditEvent
from src.models.job import JobStatus, RemediationJob
from src.schemas.api import EventOut, GraphTrace, JobDetail, JobList, JobOut, TraceStep
from src.services.task_queue import TaskQueue

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"], dependencies=Authed)

# Fields of the agent state exposed by the trace (no source code, prompts or file contents).
TRACE_FIELDS = ("fix_attempt", "terminal_status", "error", "failure_reason", "confidence_score", "reachable",
                "test_delta_passed", "scanner_cve_resolved", "branch_name", "pr_url", "run_id")  # fmt: skip
MAX_EVENTS = 1000


def to_out(job: RemediationJob) -> JobOut:
    """ORM -> API model."""
    return JobOut(
        job_id=str(job.job_id), cve_id=job.cve_id, repo_name=job.repo_name, status=job.status.value, affected_package=job.affected_package,
        installed_version=job.installed_version, target_version=job.target_version, manifest_file=job.manifest_file,
        confidence_score=job.confidence_score, breaking_change_risk=job.breaking_change_risk, pr_url=job.pr_url, pr_number=job.pr_number,
        jira_issue_key=job.jira_issue_key, confluence_page_url=job.confluence_page_url, attempt_count=job.attempt_count,
        created_at=job.created_at, updated_at=job.updated_at,
    )  # fmt: skip


def parse_id(job_id: str) -> uuid.UUID:
    """Path parameter -> UUID (422 for garbage)."""
    try:
        return uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(422, "job_id must be a UUID") from None


async def get_job_or_404(session: AsyncSession, job_id: str) -> RemediationJob:
    """Load a job or raise 404."""
    job = await session.get(RemediationJob, parse_id(job_id))
    if job is None:
        raise HTTPException(404, "job not found")
    return job


async def transition(
    session: AsyncSession, job_id: str, *, expect: JobStatus, to: JobStatus, event: str, verb: str
) -> RemediationJob:
    """Atomically move a job ``expect`` -> ``to`` (409 if it is in another state) and record an audit event."""
    uid = parse_id(job_id)
    moved = (
        await session.execute(
            update(RemediationJob).where(RemediationJob.job_id == uid, RemediationJob.status == expect).values(status=to).returning(RemediationJob.job_id)
        )
    ).first()
    job = await session.get(RemediationJob, uid, populate_existing=True)
    if job is None:
        raise HTTPException(404, "job not found")
    if moved is None:
        raise HTTPException(409, f"cannot {verb} a job that is {job.status.value} (only {expect.value} jobs can be {verb}d)")
    session.add(AuditEvent(job_id=uid, cve_id=job.cve_id, repo_name=job.repo_name, event_type=event, payload={"via": "control-api"}))
    return job


@router.get("", response_model=JobList)
async def list_jobs(
    status: JobStatus | None = None,
    repo: str | None = Query(default=None, description="exact repository name (org/name), case-insensitive"),
    cve: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> JobList:
    """List jobs, newest first, filtered by status, repo, CVE and creation date."""
    conditions = []
    if status:
        conditions.append(RemediationJob.status == status)
    if repo:
        conditions.append(func.lower(RemediationJob.repo_name) == repo.lower())
    if cve:
        conditions.append(RemediationJob.cve_id == cve.upper())
    if created_from:
        conditions.append(RemediationJob.created_at >= created_from)
    if created_to:
        conditions.append(RemediationJob.created_at <= created_to)
    total = (await session.execute(select(func.count()).select_from(RemediationJob).where(*conditions))).scalar_one()
    rows = (
        await session.execute(select(RemediationJob).where(*conditions).order_by(RemediationJob.created_at.desc(), RemediationJob.job_id).limit(limit).offset(offset))
    ).scalars()
    return JobList(total=total, limit=limit, offset=offset, items=[to_out(j) for j in rows])


@router.get("/{job_id}", response_model=JobDetail)
async def job_detail(job_id: str, session: AsyncSession = Depends(get_session)) -> JobDetail:
    """Full job detail with its audit trail."""
    job = await get_job_or_404(session, job_id)
    events = (
        await session.execute(select(AuditEvent).where(AuditEvent.job_id == job.job_id).order_by(AuditEvent.ts, AuditEvent.id).limit(MAX_EVENTS))
    ).scalars()
    return JobDetail(
        **to_out(job).model_dump(), confidence_breakdown=job.confidence_breakdown or {}, llm_explanation=job.llm_explanation,
        baseline_tests=job.baseline_tests or {}, postfix_tests=job.postfix_tests or {},
        events=[EventOut(ts=e.ts, event_type=e.event_type, payload=e.payload) for e in events],
        graph_trace_url=f"{settings.CONTROL_API_URL.rstrip('/')}/api/v1/jobs/{job.job_id}/graph-trace",
    )  # fmt: skip


@router.get("/{job_id}/graph-trace", response_model=GraphTrace)
async def graph_trace(
    job_id: str, session: AsyncSession = Depends(get_session), factory: GraphFactory = Depends(get_graph_factory)
) -> GraphTrace:
    """The job's LangGraph checkpoint history (oldest first): which node ran, what runs next, and key state fields."""
    job = await get_job_or_404(session, job_id)
    config = {"configurable": {"thread_id": str(job.job_id)}}
    async with factory() as graph:
        history = [snap async for snap in graph.aget_state_history(config)]
    if not history:
        raise HTTPException(404, "no checkpoints recorded for this job (it has not started)")
    history.reverse()
    steps: list[TraceStep] = []
    previous_next: list[str] = []
    for snap in history:
        values: dict[str, Any] = dict(snap.values or {})
        state = {k: _clean(values.get(k)) for k in TRACE_FIELDS if values.get(k) is not None}
        state["audit_event_count"] = len(values.get("audit_events") or [])
        steps.append(TraceStep(
            step=(snap.metadata or {}).get("step"), checkpoint_id=snap.config["configurable"]["checkpoint_id"], created_at=snap.created_at,
            ran=previous_next, next=_nodes(snap.next), state=state,
        ))  # fmt: skip
        previous_next = _nodes(snap.next)
    return GraphTrace(job_id=str(job.job_id), steps=steps)


def _nodes(names: Any) -> list[str]:
    """Node names without LangGraph's internal ``__start__`` / ``__end__`` markers."""
    return [n for n in names if not str(n).startswith("__")]


def _clean(value: Any) -> Any:
    return redact_text(value)[:500] if isinstance(value, str) else value


@router.delete("/{job_id}", response_model=JobOut)
async def cancel_job(job_id: str, session: AsyncSession = Depends(get_session)) -> JobOut:
    """Cancel a job that has not started yet (a queued worker message for it will find it cancelled and skip it)."""
    return to_out(await transition(session, job_id, expect=JobStatus.QUEUED, to=JobStatus.CANCELLED, event="JOB_CANCELLED", verb="cancel"))


@router.patch("/{job_id}/pause", response_model=JobOut)
async def pause_job(job_id: str, session: AsyncSession = Depends(get_session)) -> JobOut:
    """Ask a running job to pause. It stops between graph steps, releases its sandbox and keeps its checkpoint."""
    return to_out(await transition(session, job_id, expect=JobStatus.RUNNING, to=JobStatus.PAUSED, event="JOB_PAUSED", verb="pause"))


@router.post("/{job_id}/resume", status_code=202, response_model=JobOut)
async def resume_job(job_id: str, queue: TaskQueue = Depends(get_queue)) -> JobOut:
    """Resume a paused job from its LangGraph checkpoint.

    Uses its own transaction: the job must be committed as QUEUED *before* the worker message is sent.
    """
    uid = parse_id(job_id)
    async with session_scope() as session:
        job = await get_job_or_404(session, job_id)
        if job.status != JobStatus.PAUSED:
            raise HTTPException(409, f"cannot resume a job that is {job.status.value} (only PAUSED jobs can be resumed)")
        queued = (
            await session.execute(
                select(AuditEvent.payload).where(AuditEvent.job_id == uid, AuditEvent.event_type == "JOB_QUEUED")
                .order_by(AuditEvent.ts.desc(), AuditEvent.id.desc()).limit(1)
            )
        ).scalar_one_or_none()  # fmt: skip
        state = (queued or {}).get("initial_state")
        if not state:
            raise HTTPException(409, "this job has no recorded initial state, so it cannot be resumed (re-queue it through a scan instead)")
        out = to_out(await transition(session, job_id, expect=JobStatus.PAUSED, to=JobStatus.QUEUED, event="JOB_RESUMED", verb="resume"))
    queue.enqueue_fix(job_id, state)
    return out
