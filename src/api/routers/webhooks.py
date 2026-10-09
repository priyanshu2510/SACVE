"""Inbound GitHub webhooks (HMAC-verified; not API-key authenticated because GitHub cannot send the key)."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select

from src.agent.deps import get_dispatcher, get_idempotency_store
from src.api.dependencies import check_ip, get_queue
from src.core.config import settings
from src.core.database import session_scope
from src.models.audit import AuditEvent
from src.models.job import Repo
from src.services.matcher.repo_filter import load_repo_filter
from src.services.notifications.base import Notification, resolve_recipients
from src.services.pr_outcomes import record_pr_closed
from src.services.task_queue import TaskQueue

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])
MAX_BODY_BYTES = 5 * 1024 * 1024
ADVISORY_EVENTS = {"security_advisory", "repository_advisory"}


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    """Constant-time check of GitHub's ``X-Hub-Signature-256`` (``sha256=<hex HMAC of the raw body>``)."""
    if not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header, expected)


@router.post("/github", status_code=202)
async def github_webhook(
    request: Request,
    queue: TaskQueue = Depends(get_queue),
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
) -> dict[str, Any]:
    """Handle ``push`` (refresh the SBOM), ``pull_request`` closed (record the outcome) and advisory events."""
    check_ip(request)
    secret = settings.GITHUB_WEBHOOK_SECRET.get_secret_value() if settings.GITHUB_WEBHOOK_SECRET else ""
    if not secret:
        raise HTTPException(503, "webhook secret is not configured")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(413, "payload too large")
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, "payload too large")
    if not verify_signature(secret, body, x_hub_signature_256):
        raise HTTPException(401, "invalid signature")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "payload is not JSON") from None

    if x_github_event == "ping":
        return {"status": "ok", "message": "pong"}
    idem = get_idempotency_store()
    delivery_key = f"gh_delivery:{x_github_delivery}" if x_github_delivery else None
    if delivery_key and await idem.get(delivery_key) is not None:
        return {"status": "ignored", "reason": "duplicate delivery"}

    result = await _dispatch(x_github_event or "", payload, queue)
    if delivery_key:
        await idem.put(delivery_key, "webhook", {"event": x_github_event})
    return result


async def _dispatch(event: str, payload: dict[str, Any], queue: TaskQueue) -> dict[str, Any]:
    if event == "push":
        return await _on_push(payload, queue)
    if event == "pull_request" and payload.get("action") == "closed":
        return await _on_pr_closed(payload, queue)
    if event in ADVISORY_EVENTS and payload.get("action") in {"published", "updated", "performed"}:
        return {"status": "accepted", "action": "cve_sync_queued", "task_id": queue.sync_cves()}
    return {"status": "ignored", "reason": f"event {event!r} is not handled"}


async def _on_push(payload: dict[str, Any], queue: TaskQueue) -> dict[str, Any]:
    repo = payload.get("repository") or {}
    name, default = repo.get("full_name", ""), repo.get("default_branch", "")
    if not name or payload.get("ref") != f"refs/heads/{default}":
        return {"status": "ignored", "reason": "not a push to the default branch"}
    async with session_scope() as s:
        row = (await s.execute(select(Repo).where(Repo.full_name == name))).scalar_one_or_none()
        allowed = (await load_repo_filter(s)).allows(name, archived=bool(repo.get("archived")), topics=repo.get("topics") or [])
        if row is not None:
            allowed = allowed and (await load_repo_filter(s)).allows(name, archived=row.archived, topics=list(row.topics or []))
    if not allowed:
        return {"status": "ignored", "reason": "repository is out of scope"}
    return {"status": "accepted", "action": "sbom_queued", "repo": name, "task_id": queue.generate_sbom(name)}


async def _on_pr_closed(payload: dict[str, Any], queue: TaskQueue) -> dict[str, Any]:
    async with session_scope() as s:
        outcome = await record_pr_closed(s, payload)
        owners: list[str] = []
        if outcome is not None and outcome.first_time:
            from uuid import UUID

            raised = (await s.execute(select(AuditEvent.payload).where(AuditEvent.job_id == UUID(outcome.job_id), AuditEvent.event_type == "PR_RAISED")
                                      .order_by(AuditEvent.id.desc()).limit(1))).scalar_one_or_none()  # fmt: skip
            owners = (raised or {}).get("owners", [])
    if outcome is None:
        return {"status": "ignored", "reason": "not a pull request raised by this platform"}
    if not outcome.first_time:
        return {"status": "ignored", "reason": "outcome already recorded", "job_id": outcome.job_id}

    merged = outcome.kind.value != "CLOSED_UNMERGED"
    if merged:
        try:
            await get_dispatcher().dispatch(Notification(
                event="PR_MERGED", job_id=outcome.job_id, cve_id=outcome.cve_id, repo_name=outcome.repo_name, severity="INFO",
                subject=f"Security fix merged: {outcome.cve_id} in {outcome.repo_name.split('/')[-1]}",
                body=f"The fix for {outcome.cve_id} was merged ({outcome.kind.value.lower().replace('_', ' ')}).\n{outcome.pr_url or ''}",
                recipients=resolve_recipients(owners), metadata={"pr_url": outcome.pr_url, "outcome": outcome.kind.value},
            ))  # fmt: skip
        except Exception as exc:  # noqa: BLE001 - the outcome is already recorded
            log.error("webhook.notify_failed", job_id=outcome.job_id, error=str(exc))
    queue.sync_tracking(outcome.job_id)  # JIRA -> Done / Blocked, Confluence page refreshed
    return {"status": "accepted", "action": "outcome_recorded", "job_id": outcome.job_id, "outcome": outcome.kind.value}
