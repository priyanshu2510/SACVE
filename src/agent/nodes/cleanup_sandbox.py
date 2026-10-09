"""Node 10: always tear the sandbox down and settle the final status."""

from __future__ import annotations

from typing import Any

import structlog

from src.agent.deps import get_sandbox_manager
from src.agent.nodes._common import make_event
from src.agent.state import AgentState

log = structlog.get_logger(__name__)


async def cleanup_sandbox(state: AgentState) -> dict[str, Any]:
    """Force-remove the container (never raises) and map an exhausted repair loop to ``BLOCKED``."""
    events = [*state.audit_events]
    update: dict[str, Any] = {}
    if state.sandbox_container_id:
        try:
            await get_sandbox_manager().remove(state.sandbox_container_id)
            events.append(make_event("SANDBOX_REMOVED", {"container": state.sandbox_container_id[:12]}))
        except Exception as exc:  # noqa: BLE001 - teardown must not fail the job; the label sweep reclaims leaks
            log.error("cleanup.remove_failed", container=state.sandbox_container_id[:12], error=str(exc), job_id=state.job_id)
            events.append(make_event("SANDBOX_REMOVED", {"container": state.sandbox_container_id[:12], "error": str(exc)}))
        update["sandbox_container_id"] = None
    if state.terminal_status is None and state.failure_reason:
        update["terminal_status"] = "BLOCKED"
        events.append(make_event("JOB_BLOCKED", {"reason": state.failure_reason[:2000], "attempts": state.fix_attempt}))
    update["audit_events"] = events
    return update
