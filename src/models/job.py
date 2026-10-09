"""Repository, remediation job, impact and idempotency ORM models."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.core.database import Base


class JobStatus(str, enum.Enum):
    """Remediation job lifecycle states."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    FIX_GENERATED = "FIX_GENERATED"
    SANDBOX_RUNNING = "SANDBOX_RUNNING"
    TESTING = "TESTING"
    SCAN_RUNNING = "SCAN_RUNNING"
    PR_RAISED = "PR_RAISED"
    MERGED = "MERGED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    NOT_REACHABLE = "NOT_REACHABLE"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"


class Repo(Base):
    """A GitHub repository tracked by the platform."""

    __tablename__ = "repos"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    full_name: Mapped[str] = mapped_column(String(255), unique=True)
    default_branch: Mapped[str] = mapped_column(String(128), default="main")
    language: Mapped[str | None] = mapped_column(String(32))
    archived: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    topics: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RemediationJob(Base):
    """One remediation job per ``{cve_id, repo_id}`` pair (also the LangGraph thread id)."""

    __tablename__ = "remediation_jobs"

    job_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.cve_id"))
    repo_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repos.id"))
    repo_name: Mapped[str] = mapped_column(String(255))
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, native_enum=False, length=32), default=JobStatus.QUEUED
    )
    affected_package: Mapped[str] = mapped_column(String(512))
    installed_version: Mapped[str] = mapped_column(String(128))
    target_version: Mapped[str] = mapped_column(String(128))
    manifest_file: Mapped[str] = mapped_column(String(512))
    confidence_score: Mapped[int | None] = mapped_column(Integer)
    confidence_breakdown: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    llm_explanation: Mapped[str | None] = mapped_column(Text)
    breaking_change_risk: Mapped[str | None] = mapped_column(String(16))
    baseline_tests: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    postfix_tests: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    pr_url: Mapped[str | None] = mapped_column(String(512))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    jira_issue_key: Mapped[str | None] = mapped_column(String(32))
    confluence_page_url: Mapped[str | None] = mapped_column(String(512))
    langgraph_thread_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("cve_id", "repo_id", name="uq_job_cve_repo"),
        Index("ix_jobs_status", "status"),
    )


class CVERepoImpact(Base):
    """Result of matching a CVE against a repo's SBOM."""

    __tablename__ = "cve_repo_impact"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    repo_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repos.id"))
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.cve_id"))
    affected_package: Mapped[str] = mapped_column(String(512))
    installed_version: Mapped[str] = mapped_column(String(128))
    safe_version: Mapped[str | None] = mapped_column(String(128))
    manifest_file_path: Mapped[str] = mapped_column(String(512))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("repo_id", "cve_id", "affected_package", name="uq_impact"),)


class IdempotencyKey(Base):
    """Check-before-create guard for external side effects (PRs, tickets, notifications, audit)."""

    __tablename__ = "idempotency_keys"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    scope: Mapped[str] = mapped_column(String(32))
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


__all__ = ["CVERepoImpact", "IdempotencyKey", "JobStatus", "RemediationJob", "Repo"]
