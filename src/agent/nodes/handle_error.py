"""Node 14: terminal error handling."""

from __future__ import annotations

from typing import Any

import structlog

from src.agent.routing import MIN_CONFIDENCE_TO_PROCEED
from src.agent.state import AgentState
from src.agent.nodes._common import agent_node, with_event

log = structlog.get_logger(__name__)


@agent_node("handle_error")
async def handle_error(state: AgentState) -> dict[str, Any]:
    """Log the failure with state context and mark the job ``FAILED``.

    Also covers the "confidence too low" route, where no exception was raised.
    """
    error = state.error
    if not error and state.confidence_score is not None and state.confidence_score < MIN_CONFIDENCE_TO_PROCEED:
        error = f"confidence score {state.confidence_score} is below the minimum of {MIN_CONFIDENCE_TO_PROCEED}"
    error = error or "unknown error"

    log.error(
        "job.failed",
        error=error,
        cve_id=state.cve_id,
        repo=state.repo_name,
        package=state.affected_package,
        fix_attempt=state.fix_attempt,
        confidence_score=state.confidence_score,
        sandbox_container_id=state.sandbox_container_id,
        audit_event_count=len(state.audit_events),
    )
    return {
        "error": error,
        "terminal_status": "FAILED",
        "audit_events": with_event(
            state,
            "JOB_FAILED",
            {"error": error, "fix_attempt": state.fix_attempt, "confidence_score": state.confidence_score},
        ),
    }
