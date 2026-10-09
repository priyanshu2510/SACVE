"""PagerDuty channel (Events API v2): only for SLA escalations of critical CVEs."""

from __future__ import annotations

from typing import Any

import httpx

from src.core.config import Settings, secret_value, settings as default_settings
from src.services.notifications.base import Notification, NotificationHandler

EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
MIN_CVSS_FOR_PAGE = 9.0


class PagerDutyHandler(NotificationHandler):
    """Triggers an incident for ``ESCALATED`` events with CVSS >= 9.0 (the escalation task sets ``metadata.cvss``)."""

    name = "pagerduty"

    def __init__(self, cfg: Settings | None = None, client: httpx.AsyncClient | None = None) -> None:
        self._cfg = cfg or default_settings
        self._client = client or httpx.AsyncClient(timeout=self._cfg.CVE_HTTP_TIMEOUT_SECONDS)

    def supports(self, notification: Notification) -> bool:
        """Escalations of CVSS >= 9.0 only."""
        return notification.event == "ESCALATED" and float(notification.metadata.get("cvss", 0)) >= MIN_CVSS_FOR_PAGE

    async def send(self, notification: Notification) -> dict[str, Any]:
        """Trigger (idempotent per CVE+repo via ``dedup_key``)."""
        resp = await self._client.post(
            EVENTS_URL,
            json={
                "routing_key": secret_value(self._cfg.PAGERDUTY_ROUTING_KEY, "PAGERDUTY_ROUTING_KEY"),
                "event_action": "trigger",
                "dedup_key": f"cve-remediation:{notification.cve_id}:{notification.repo_name}",
                "payload": {
                    "summary": notification.subject[:1024],
                    "source": notification.repo_name,
                    "severity": "critical",
                    "custom_details": {"cve_id": notification.cve_id, **notification.metadata},
                },
            },
        )
        resp.raise_for_status()
        return {"status_code": resp.status_code}
