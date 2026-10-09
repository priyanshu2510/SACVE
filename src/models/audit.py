"""Append-only audit trail and PR outcome ORM models."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Index, Integer, String, UniqueConstraint, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.core.database import Base


class EventType(str, enum.Enum):
    """All audit event types (spec list plus v1 locked additions)."""

    CVE_DETECTED = "CVE_DETECTED"
    REPO_MATCHED = "REPO_MATCHED"
    JOB_QUEUED = "JOB_QUEUED"
    CONTEXT_ASSEMBLED = "CONTEXT_ASSEMBLED"
    REACHABILITY_ASSESSED = "REACHABILITY_ASSESSED"
    FIX_GENERATED = "FIX_GENERATED"
    FIX_ATTEMPT_FAILED = "FIX_ATTEMPT_FAILED"
    CONFIDENCE_SCORED = "CONFIDENCE_SCORED"
    SANDBOX_STARTED = "SANDBOX_STARTED"
    SANDBOX_REMOVED = "SANDBOX_REMOVED"
    PRE_TESTS_PASSED = "PRE_TESTS_PASSED"
    PRE_TESTS_FAILED = "PRE_TESTS_FAILED"
    PATCH_APPLIED = "PATCH_APPLIED"
    POST_TESTS_PASSED = "POST_TESTS_PASSED"
    POST_TESTS_FAILED = "POST_TESTS_FAILED"
    SCAN_CONFIRMED = "SCAN_CONFIRMED"
    SCAN_FAILED = "SCAN_FAILED"
    PR_RAISED = "PR_RAISED"
    PR_DEDUPLICATED = "PR_DEDUPLICATED"
    PR_MERGED = "PR_MERGED"
    PR_MERGED_CLEAN = "PR_MERGED_CLEAN"
    PR_MERGED_EDITED = "PR_MERGED_EDITED"
    PR_CLOSED_UNMERGED = "PR_CLOSED_UNMERGED"
    NOTIFICATION_SENT = "NOTIFICATION_SENT"
    ESCALATED = "ESCALATED"
    JOB_FAILED = "JOB_FAILED"
    JOB_BLOCKED = "JOB_BLOCKED"
    JOB_CANCELLED = "JOB_CANCELLED"
    JOB_PAUSED = "JOB_PAUSED"
    JOB_RESUMED = "JOB_RESUMED"


class PROutcomeKind(str, enum.Enum):
    """How a bot PR ended (captured from the GitHub webhook)."""

    MERGED_CLEAN = "MERGED_CLEAN"
    MERGED_EDITED = "MERGED_EDITED"
    CLOSED_UNMERGED = "CLOSED_UNMERGED"


class AuditEvent(Base):
    """One audit event. Append-only: a DB trigger rejects UPDATE and DELETE (see migration 0001)."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    cve_id: Mapped[str | None] = mapped_column(String(32))
    repo_name: Mapped[str | None] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(48))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_audit_job", "job_id", "ts"),
        Index("ix_audit_cve", "cve_id"),
    )


class PROutcome(Base):
    """Predicted-vs-actual record used to recalibrate confidence tiers."""

    __tablename__ = "pr_outcomes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    repo_name: Mapped[str] = mapped_column(String(255))
    pr_number: Mapped[int] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(24))
    predicted_confidence: Mapped[int | None] = mapped_column(Integer)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("job_id", name="uq_pr_outcome_job"),)
