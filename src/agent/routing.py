"""Conditional-edge functions. Pure: they read state and return the next node's name."""

from __future__ import annotations

from src.agent.state import AgentState

MIN_CONFIDENCE_TO_PROCEED = 20

# Terminal statuses that end the job without a PR but are *not* errors.
NOT_REACHABLE = "NOT_REACHABLE"
BASELINE_FAILING = "BASELINE_FAILING"


def _can_retry(state: AgentState) -> bool:
    """True while the repair loop still has attempts left."""
    return state.fix_attempt < state.max_fix_attempts


def route_after_context(state: AgentState) -> str:
    """``assess_reachability`` unless context assembly failed."""
    return "handle_error" if state.error else "assess_reachability"


def route_after_reachability(state: AgentState) -> str:
    """Unreachable + enforce mode skips straight to audit; errors go to ``handle_error``."""
    if state.error:
        return "handle_error"
    if state.terminal_status == NOT_REACHABLE:
        return "write_audit"
    return "generate_fix"


def route_after_fix(state: AgentState) -> str:
    """``score_confidence`` unless the LLM step failed."""
    return "handle_error" if state.error else "score_confidence"


def route_after_scoring(state: AgentState) -> str:
    """Proceed only for an error-free fix with a usable confidence score.

    On a repair attempt the sandbox already exists and has passed its baseline, so skip
    straight to ``apply_patch`` (which resets the workspace first).
    """
    if state.error:
        return "handle_error"
    if state.confidence_score is None or state.confidence_score < MIN_CONFIDENCE_TO_PROCEED:
        return "handle_error"
    return "apply_patch" if state.sandbox_container_id else "run_sandbox"


def route_after_sandbox(state: AgentState) -> str:
    """A repo that cannot even build its baseline ends via cleanup with its specific status."""
    if state.error:
        return "handle_error"
    if state.terminal_status:
        return "cleanup_sandbox"
    return "run_pre_tests"


def route_after_pre_tests(state: AgentState) -> str:
    """A failing baseline / missing tests keep their specific status via cleanup; errors go to ``handle_error``."""
    if state.error:
        return "handle_error"
    if state.terminal_status:
        return "cleanup_sandbox"
    return "apply_patch"


def route_after_patch(state: AgentState) -> str:
    """A patch that does not apply feeds the repair loop like any other failed attempt."""
    if state.error:
        return "handle_error"
    if state.failure_reason is None:
        return "resolve_dependencies"
    return "generate_fix" if _can_retry(state) else "cleanup_sandbox"


def route_after_resolve(state: AgentState) -> str:
    """Dependency resolution failure feeds the repair loop; exhausted attempts end BLOCKED."""
    if state.error:
        return "handle_error"
    if state.failure_reason is None:
        return "run_post_tests"
    return "generate_fix" if _can_retry(state) else "cleanup_sandbox"


def route_after_post_tests(state: AgentState) -> str:
    """A regression retries via ``generate_fix`` while attempts remain, else BLOCKED via cleanup."""
    if state.error:
        return "handle_error"
    if state.failure_reason is None:
        return "run_security_scan"
    return "generate_fix" if _can_retry(state) else "cleanup_sandbox"


def route_after_scan(state: AgentState) -> str:
    """CVE still present retries while attempts remain; a resolved CVE heads to cleanup."""
    if state.error:
        return "handle_error"
    if state.failure_reason is None:
        return "cleanup_sandbox"
    return "generate_fix" if _can_retry(state) else "cleanup_sandbox"


def route_after_cleanup(state: AgentState) -> str:
    """Raise a PR only for a fully validated fix; every other outcome goes to audit."""
    if (
        state.terminal_status is None
        and state.error is None
        and state.failure_reason is None
        and state.test_delta_passed is True
        and state.scanner_cve_resolved is True
    ):
        return "create_pr"
    return "write_audit"


def route_after_pr(state: AgentState) -> str:
    """Notify owners of a newly raised PR; a deduplicated (already existing) PR needs no new notification."""
    if state.error:
        return "handle_error"
    if state.terminal_status == "PR_EXISTS":
        return "write_audit"
    return "notify_owners"
