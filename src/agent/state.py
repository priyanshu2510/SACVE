"""LangGraph agent state."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class FileChange(BaseModel):
    """One proposed edit. ``original_content``/``new_content`` are the changed section."""

    file_path: str
    original_content: str
    new_content: str
    change_description: str


class TestResult(BaseModel):
    """Outcome of one test-suite run inside the sandbox."""

    __test__ = False  # not a pytest class

    total: int
    passed: int
    failed: int
    skipped: int
    stdout: str
    failed_test_names: list[str] = Field(default_factory=list)


class AgentState(BaseModel):
    """State accumulated as a job flows through the fix-agent graph."""

    # Input (set at graph entry)
    job_id: str
    run_id: str = ""  # one per enqueue: distinguishes a re-queued job's new run from a resume of the same run
    cve_id: str
    repo_name: str  # e.g. "org/api-gateway"
    ecosystem: str = "pip"  # npm | pip | maven | go | nuget | gem
    affected_package: str
    installed_version: str
    target_version: str
    manifest_file_path: str
    cvss_score: float
    severity: str
    max_fix_attempts: int = 3  # copied from settings by the runner so routers stay pure

    # Assembled context
    context_payload: Optional[dict[str, Any]] = None
    context_token_count: Optional[int] = None

    # Reachability triage
    reachable: Optional[bool] = None
    reachability_evidence: Optional[dict[str, Any]] = None

    # Fix generation output
    file_changes: Optional[list[FileChange]] = None
    llm_explanation: Optional[str] = None
    breaking_change_risk: Optional[str] = None
    breaking_change_notes: Optional[str] = None
    llm_self_confidence: Optional[int] = None
    llm_raw_response: Optional[str] = None

    # Repair loop
    fix_attempt: int = 0
    previous_attempts: list[dict[str, Any]] = Field(default_factory=list)  # {file_changes, failure_reason}
    failure_reason: Optional[str] = None  # set by a node when the current attempt failed but may be retried

    # Confidence score
    confidence_score: Optional[int] = None
    confidence_breakdown: Optional[dict[str, Any]] = None

    # Sandbox + testing
    sandbox_container_id: Optional[str] = None
    pre_fix_tests: Optional[TestResult] = None
    post_fix_tests: Optional[TestResult] = None
    test_delta_passed: Optional[bool] = None
    dependency_resolution_output: Optional[str] = None
    lockfile_changes: Optional[list[str]] = None

    # Security scan
    scanner_cve_resolved: Optional[bool] = None
    scanner_output: Optional[str] = None

    # PR output
    branch_name: Optional[str] = None
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None

    code_owners: Optional[list[str]] = None  # CODEOWNERS of the changed files (@user, @org/team, email)
    pr_warnings: list[str] = Field(default_factory=list)
    confluence_page_url: Optional[str] = None
    jira_issue_key: Optional[str] = None
    notification_results: Optional[list[dict[str, Any]]] = None

    # Control flow
    error: Optional[str] = None
    terminal_status: Optional[str] = None  # PR_RAISED / BLOCKED / FAILED / NOT_REACHABLE / ...

    # Audit
    audit_events: list[dict[str, Any]] = Field(default_factory=list)
