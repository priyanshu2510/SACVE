"""Shared helpers for graph nodes."""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

import structlog

from src.agent.state import AgentState
from src.core.logging import bind_job
from src.core.redaction import redact_obj, redact_text

log = structlog.get_logger(__name__)

NodeFn = Callable[[AgentState], Awaitable[dict[str, Any]]]


class NodeError(RuntimeError):
    """An expected, already-explained node failure (message goes to ``state.error``)."""


def utcnow() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def make_event(event_type: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build an audit event with secrets redacted from the payload."""
    return {"event_type": event_type, "payload": redact_obj(payload or {}), "ts": utcnow()}


def with_event(state: AgentState, event_type: str, payload: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return ``state.audit_events`` plus one new event (nodes never mutate state)."""
    return [*state.audit_events, make_event(event_type, payload)]


def record_failure(
    state: AgentState, reason: str, events: list[tuple[str, dict[str, Any]]] | None = None
) -> dict[str, Any]:
    """State update for a *repairable* failure of the current fix attempt.

    Sets ``failure_reason`` (which the routers use to retry or give up), appends the attempt to
    ``previous_attempts`` for the next LLM prompt, and emits the given events plus ``FIX_ATTEMPT_FAILED``.
    """
    reason = redact_text(reason)
    attempt = {
        "fix_attempt": state.fix_attempt,
        "file_changes": [c.model_dump() for c in state.file_changes or []],
        "failure_reason": reason,
    }
    all_events = [*(events or []), ("FIX_ATTEMPT_FAILED", {"attempt": state.fix_attempt, "reason": reason[:2000]})]
    return {
        "failure_reason": reason,
        "previous_attempts": [*state.previous_attempts, attempt],
        "audit_events": [*state.audit_events, *(make_event(t, p) for t, p in all_events)],
    }


def agent_node(name: str) -> Callable[[NodeFn], NodeFn]:
    """Wrap a node: bind ``job_id`` for logging and convert exceptions into ``error`` + ``FAILED``.

    Nodes still build their own ``audit_events``; ``handle_error`` records ``JOB_FAILED``.
    """

    def decorator(fn: NodeFn) -> NodeFn:
        @functools.wraps(fn)
        async def wrapper(state: AgentState) -> dict[str, Any]:
            with bind_job(state.job_id, node=name):
                try:
                    return await fn(state)
                except Exception as exc:  # noqa: BLE001 - boundary: nodes must never raise into the graph
                    log.error(f"{name}.failed", error=str(exc), cve_id=state.cve_id, repo=state.repo_name, exc_info=True)
                    message = str(exc) if isinstance(exc, NodeError) else f"{name}: {type(exc).__name__}: {exc}"
                    return {"error": message, "terminal_status": "FAILED"}

        return wrapper

    return decorator
