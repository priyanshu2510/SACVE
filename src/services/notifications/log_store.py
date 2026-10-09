"""Persistence of notification attempts (table ``notification_log``)."""

from __future__ import annotations

import uuid
from typing import Any, Protocol, runtime_checkable

from src.core.database import session_scope
from src.models.notification import NotificationLog
from src.services.notifications.base import Notification, NotificationResult


@runtime_checkable
class NotificationLogStore(Protocol):
    """Where every attempt (successful or not) is recorded."""

    async def record(self, notification: Notification, result: NotificationResult, idempotency_key: str | None) -> None:
        """Append one attempt."""


def _as_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


class DbNotificationLogStore:
    """PostgreSQL implementation."""

    async def record(self, notification: Notification, result: NotificationResult, idempotency_key: str | None) -> None:
        """Insert a ``notification_log`` row."""
        row: dict[str, Any] = {
            "idempotency_key": idempotency_key if result.status == "sent" else None,
            "job_id": _as_uuid(notification.job_id),
            "cve_id": notification.cve_id,
            "channel": result.channel,
            "recipients": notification.recipients,
            "status": result.status,
            "response": result.response,
            "error": result.error,
        }
        async with session_scope() as session:
            session.add(NotificationLog(**row))
