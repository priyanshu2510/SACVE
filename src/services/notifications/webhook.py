"""Generic signed webhook channel."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import httpx

from src.core.config import Settings, secret_value, settings as default_settings
from src.services.notifications.base import Notification, NotificationHandler


def sign(secret: str, body: bytes) -> str:
    """``sha256=<hex HMAC>`` of the exact request body (same scheme GitHub uses)."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class WebhookHandler(NotificationHandler):
    """``POST WEBHOOK_URL`` with the standard schema and an ``X-Signature-256`` header."""

    name = "webhook"

    def __init__(self, cfg: Settings | None = None, client: httpx.AsyncClient | None = None) -> None:
        self._cfg = cfg or default_settings
        self._client = client or httpx.AsyncClient(timeout=self._cfg.CVE_HTTP_TIMEOUT_SECONDS)

    def supports(self, notification: Notification) -> bool:
        """Only when a URL is configured."""
        return bool(self._cfg.WEBHOOK_URL)

    async def send(self, notification: Notification) -> dict[str, Any]:
        """Deliver; raises on non-2xx."""
        body = json.dumps(
            {
                "event": notification.event,
                "job_id": notification.job_id,
                "cve_id": notification.cve_id,
                "repo": notification.repo_name,
                "severity": notification.severity,
                "subject": notification.subject,
                "body": notification.body,
                "recipients": notification.recipients,
                "metadata": notification.metadata,
            },
            sort_keys=True,
        ).encode()
        headers = {"Content-Type": "application/json"}
        if self._cfg.WEBHOOK_SECRET:
            headers["X-Signature-256"] = sign(secret_value(self._cfg.WEBHOOK_SECRET, "WEBHOOK_SECRET"), body)
        resp = await self._client.post(str(self._cfg.WEBHOOK_URL), content=body, headers=headers)
        resp.raise_for_status()
        return {"status_code": resp.status_code}
