"""Node 12: tell the code owners about the new PR. Never fails the job."""

from __future__ import annotations

from typing import Any

import structlog

from src.agent.deps import get_dispatcher
from src.agent.nodes._common import make_event
from src.agent.state import AgentState
from src.services.github.pr_description import one_line
from src.services.notifications.base import Notification, resolve_recipients

log = structlog.get_logger(__name__)


def build_notification(state: AgentState) -> Notification:
    """The ``PR_RAISED`` message for this job."""
    short = state.repo_name.split("/")[-1]
    lines = [
        f"A fix for {state.cve_id} ({state.severity}, CVSS {state.cvss_score}) is ready for review in {state.repo_name}.",
        f"Change: {one_line(state.affected_package)} {one_line(state.installed_version)} -> {one_line(state.target_version)}",
        f"Confidence: {state.confidence_score}/100",
        f"Pull request: {state.pr_url}",
    ]
    if state.confluence_page_url:
        lines.append(f"Audit trail: {state.confluence_page_url}")
    return Notification(
        event="PR_RAISED",
        job_id=state.job_id,
        cve_id=state.cve_id,
        repo_name=state.repo_name,
        severity=state.severity,
        subject=f"CVE fix ready for review: {state.cve_id} in {short}",
        body="\n".join(lines),
        recipients=resolve_recipients(state.code_owners or []),
        metadata={
            "pr_url": state.pr_url,
            "confluence_url": state.confluence_page_url,
            "confidence_score": state.confidence_score,
            "cvss": state.cvss_score,
        },
    )


async def notify_owners(state: AgentState) -> dict[str, Any]:
    """Dispatch to every enabled channel. Delivery problems are recorded, never raised: the PR already exists."""
    try:
        results = await get_dispatcher().dispatch(build_notification(state))
    except Exception as exc:  # noqa: BLE001 - notification trouble must not demote a raised PR to FAILED
        log.error("notify_owners.failed", job_id=state.job_id, error=str(exc))
        return {
            "notification_results": [{"channel": "*", "status": "failed", "error": str(exc)[:300]}],
            "audit_events": [*state.audit_events, make_event("NOTIFICATION_SENT", {"channel": "*", "status": "failed", "error": str(exc)[:300]})],
        }
    rows = [{"channel": r.channel, "status": r.status, "error": r.error} for r in results]
    events = [make_event("NOTIFICATION_SENT", row) for row in rows] or [
        make_event("NOTIFICATION_SENT", {"channel": None, "status": "skipped", "reason": "no channel applies"})
    ]
    return {"notification_results": rows, "audit_events": [*state.audit_events, *events]}
