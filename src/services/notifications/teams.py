"""Internal Teams API channel."""

from __future__ import annotations

from typing import Any

import httpx

from src.core.config import Settings, secret_value, settings as default_settings
from src.services.notifications.base import Notification, NotificationHandler


class TeamsHandler(NotificationHandler):
    """``POST TEAMS_API_ENDPOINT`` with the structured payload from the integration spec.

    Auth header and payload are the adaptation point if the real Teams API differs.
    """

    name = "teams"

    def __init__(self, cfg: Settings | None = None, client: httpx.AsyncClient | None = None) -> None:
        self._cfg = cfg or default_settings
        self._client = client or httpx.AsyncClient(timeout=self._cfg.CVE_HTTP_TIMEOUT_SECONDS)

    def supports(self, notification: Notification) -> bool:
        """Needs somebody to notify."""
        return bool(notification.recipients)

    async def send(self, notification: Notification) -> dict[str, Any]:
        """Deliver; raises ``httpx.HTTPStatusError`` on non-2xx."""
        resp = await self._client.post(
            self._cfg.TEAMS_API_ENDPOINT,
            headers={"Authorization": f"Bearer {secret_value(self._cfg.TEAMS_API_KEY, 'TEAMS_API_KEY')}"},
            json={
                "recipients": notification.recipients,
                "subject": notification.subject,
                "body": notification.body,
                "severity": notification.severity,
                "metadata": {"cve_id": notification.cve_id, "event": notification.event, **notification.metadata},
            },
        )
        resp.raise_for_status()
        return {"status_code": resp.status_code}
