"""Fan a notification out to every enabled channel, idempotently and without ever raising."""

from __future__ import annotations

import httpx
import structlog

from src.core.config import Settings, settings as default_settings
from src.core.redaction import redact_text
from src.services.idempotency import IdempotencyStore
from src.services.notifications.base import Notification, NotificationHandler, NotificationResult
from src.services.notifications.email import EmailHandler
from src.services.notifications.log_store import NotificationLogStore
from src.services.notifications.pagerduty import PagerDutyHandler
from src.services.notifications.teams import TeamsHandler
from src.services.notifications.webhook import WebhookHandler
from src.utils.retry import retry_async

log = structlog.get_logger(__name__)

HANDLERS: dict[str, type[NotificationHandler]] = {
    "teams": TeamsHandler,
    "webhook": WebhookHandler,
    "email": EmailHandler,
    "pagerduty": PagerDutyHandler,
}


def build_handlers(cfg: Settings | None = None) -> list[NotificationHandler]:
    """Instantiate the channels listed in ``ENABLED_NOTIFICATION_CHANNELS`` (unknown names are skipped)."""
    cfg = cfg or default_settings
    handlers: list[NotificationHandler] = []
    for name in cfg.ENABLED_NOTIFICATION_CHANNELS:
        cls = HANDLERS.get(name.lower())
        if cls is None:
            log.warning("notifications.unknown_channel", channel=name)
            continue
        handlers.append(cls(cfg))
    return handlers


def _retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code == 429 or exc.response.status_code >= 500
    return isinstance(exc, (httpx.TransportError, OSError))


class NotificationDispatcher:
    """Sends each notification once per ``(job, event, channel)`` and logs every attempt."""

    def __init__(
        self, handlers: list[NotificationHandler], idempotency: IdempotencyStore, log_store: NotificationLogStore
    ) -> None:
        self._handlers = handlers
        self._idem = idempotency
        self._log = log_store

    async def dispatch(self, notification: Notification) -> list[NotificationResult]:
        """Return one result per channel that applies; delivery errors become ``failed`` results."""
        results: list[NotificationResult] = []
        for handler in self._handlers:
            if not handler.supports(notification):
                continue
            key = f"notify:{notification.job_id}:{notification.event}:{handler.name}"
            result = await self._send_one(handler, notification, key)
            try:
                await self._log.record(notification, result, key)
            except Exception as exc:  # noqa: BLE001 - a logging failure must not hide the delivery result
                log.error("notifications.log_failed", channel=handler.name, error=str(exc))
            results.append(result)
        return results

    async def _send_one(self, handler: NotificationHandler, n: Notification, key: str) -> NotificationResult:
        try:
            if await self._idem.get(key) is not None:
                return NotificationResult(handler.name, "skipped", {"reason": "already sent"})
            response = await retry_async(
                max_retries=3, base_delay=1.0, retry_on=(Exception,), is_retryable=_retryable
            )(handler.send)(n)
            await self._idem.put(key, "notification", {"channel": handler.name})
            return NotificationResult(handler.name, "sent", response)
        except Exception as exc:  # noqa: BLE001 - one broken channel must not stop the others
            log.error("notifications.send_failed", channel=handler.name, job_id=n.job_id, error=str(exc))
            return NotificationResult(handler.name, "failed", error=redact_text(f"{type(exc).__name__}: {exc}")[:500])
