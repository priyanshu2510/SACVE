"""Pydantic schemas of the Control API."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

# 'name' or 'org/name'; a segment made only of dots ('.', '..') is path traversal, not a repository
_REPO_ENTRY = re.compile(r"^(?!\.{1,2}(?:/|$))[A-Za-z0-9_.-]+(?:/(?!\.{1,2}$)[A-Za-z0-9_.-]+)?$")
MAX_REPO_ENTRIES = 500


class ScanTrigger(BaseModel):
    """Body of ``POST /scan/trigger``."""

    repo_names: list[str] | None = Field(default=None, max_length=MAX_REPO_ENTRIES)

    @field_validator("repo_names")
    @classmethod
    def _valid(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and not all(_REPO_ENTRY.match(x) for x in v):
            raise ValueError("repo names must look like 'name' or 'org/name'")
        return v


class Accepted(BaseModel):
    """A request that was queued for a worker."""

    status: str = "accepted"
    task_ids: dict[str, str] = Field(default_factory=dict)


class JobOut(BaseModel):
    """A remediation job."""

    job_id: str
    cve_id: str
    repo_name: str
    status: str
    affected_package: str
    installed_version: str
    target_version: str
    manifest_file: str
    confidence_score: int | None = None
    breaking_change_risk: str | None = None
    pr_url: str | None = None
    pr_number: int | None = None
    jira_issue_key: str | None = None
    confluence_page_url: str | None = None
    attempt_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None


class EventOut(BaseModel):
    """One audit event."""

    ts: datetime
    event_type: str
    payload: dict[str, Any]


class JobDetail(JobOut):
    """A job plus its audit trail."""

    confidence_breakdown: dict[str, Any] = Field(default_factory=dict)
    llm_explanation: str | None = None
    baseline_tests: dict[str, Any] = Field(default_factory=dict)
    postfix_tests: dict[str, Any] = Field(default_factory=dict)
    events: list[EventOut] = Field(default_factory=list)
    graph_trace_url: str


class JobList(BaseModel):
    """A page of jobs."""

    total: int
    limit: int
    offset: int
    items: list[JobOut]


class TraceStep(BaseModel):
    """One LangGraph checkpoint (a snapshot of the run after a graph step)."""

    step: int | None
    checkpoint_id: str
    created_at: str | None
    ran: list[str] = Field(description="Node(s) that executed to produce this checkpoint")
    next: list[str] = Field(description="Node(s) that will run next")
    state: dict[str, Any] = Field(description="Allow-listed, redacted subset of the agent state")


class GraphTrace(BaseModel):
    """Checkpoint history of a job, oldest first."""

    job_id: str
    steps: list[TraceStep]


class CVEOut(BaseModel):
    """A detected CVE with its match / fix status."""

    cve_id: str
    title: str | None
    severity: str | None
    cvss: float | None
    cisa_kev: bool
    published_at: datetime | None
    affected_repos: int
    jobs: dict[str, int]
    fix_status: str


class CVEList(BaseModel):
    """A page of CVEs."""

    total: int
    limit: int
    offset: int
    items: list[CVEOut]


class RepoConfig(BaseModel):
    """Effective repository allow/block lists."""

    allowlist: list[str]
    blocklist: list[str]
    source: str  # override | static


class RepoConfigUpdate(BaseModel):
    """Body of ``PATCH /config/repos``; omitted fields keep their current value."""

    allowlist: list[str] | None = Field(default=None, max_length=MAX_REPO_ENTRIES)
    blocklist: list[str] | None = Field(default=None, max_length=MAX_REPO_ENTRIES)

    @field_validator("allowlist", "blocklist")
    @classmethod
    def _valid(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and not all(_REPO_ENTRY.match(x) for x in v):
            raise ValueError("entries must look like 'name' or 'org/name'")
        return v


class Health(BaseModel):
    """Liveness / dependency health."""

    status: str
    checks: dict[str, bool]
    automation_enabled: bool
