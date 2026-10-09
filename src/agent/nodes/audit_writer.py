"""Node 13: persist the audit trail and the final job state."""

from __future__ import annotations

from typing import Any

import structlog

from src.agent.deps import get_audit_store, get_post_audit_hook
from src.agent.state import AgentState
from src.core.redaction import redact_obj
from src.services.audit.store import JobSummary

log = structlog.get_logger(__name__)


def _tests(result: Any) -> dict[str, Any] | None:
    if result is None:
        return None
    data = result.model_dump()
    data["stdout"] = data["stdout"][-2000:]
    return data


async def write_audit(state: AgentState) -> dict[str, Any]:
    """Flush all accumulated events (append-only) and update the job row in one transaction.

    Deliberately NOT wrapped in ``agent_node`` and not routed to ``handle_error``: if persistence fails
    the exception propagates, the checkpoint stays *before* this node, and the Celery retry resumes
    exactly here. The flush is idempotent per job, so a resume never duplicates events.
    """
    summary = JobSummary(
        job_id=state.job_id,
        run_id=state.run_id,
        cve_id=state.cve_id,
        repo_name=state.repo_name,
        terminal_status=state.terminal_status,
        confidence_score=state.confidence_score,
        confidence_breakdown=state.confidence_breakdown,
        llm_explanation=state.llm_explanation,
        breaking_change_risk=state.breaking_change_risk,
        baseline_tests=_tests(state.pre_fix_tests),
        postfix_tests=_tests(state.post_fix_tests),
        pr_url=state.pr_url,
        pr_number=state.pr_number,
        jira_issue_key=state.jira_issue_key,
        confluence_page_url=state.confluence_page_url,
        attempt_count=state.fix_attempt,
    )
    flushed = await get_audit_store().flush(summary, redact_obj(state.audit_events))
    log.info("audit.flushed" if flushed else "audit.already_flushed", events=len(state.audit_events), status=state.terminal_status)
    if flushed:
        try:
            await get_post_audit_hook()(state.job_id)  # e.g. enqueue the Confluence page update
        except Exception as exc:  # noqa: BLE001 - a failed follow-up must not re-run the audit node
            log.error("audit.post_hook_failed", job_id=state.job_id, error=str(exc))
    return {}
