"""SMTP email channel."""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage
from typing import Any, Callable

from src.core.config import Settings, secret_value, settings as default_settings
from src.services.notifications.base import Notification, NotificationHandler


class EmailHandler(NotificationHandler):
    """Send via ``SMTP_HOST``/``SMTP_PORT`` with STARTTLS (blocking smtplib runs in a worker thread)."""

    name = "email"

    def __init__(self, cfg: Settings | None = None, smtp_factory: Callable[..., Any] = smtplib.SMTP) -> None:
        self._cfg = cfg or default_settings
        self._smtp = smtp_factory

    def supports(self, notification: Notification) -> bool:
        """Needs SMTP configured and at least one email recipient."""
        return bool(self._cfg.SMTP_HOST and self._cfg.EMAIL_FROM and notification.email_recipients)

    async def send(self, notification: Notification) -> dict[str, Any]:
        """Deliver one message to all email recipients."""
        msg = EmailMessage()
        msg["Subject"] = " ".join(notification.subject.split())  # no header injection via newlines
        msg["From"] = self._cfg.EMAIL_FROM
        msg["To"] = ", ".join(notification.email_recipients)
        msg.set_content(notification.body)

        def _send() -> None:
            with self._smtp(self._cfg.SMTP_HOST, self._cfg.SMTP_PORT, timeout=30) as server:
                server.starttls()
                if self._cfg.SMTP_USER and self._cfg.SMTP_PASSWORD:
                    server.login(self._cfg.SMTP_USER, secret_value(self._cfg.SMTP_PASSWORD, "SMTP_PASSWORD"))
                server.send_message(msg)

        await asyncio.to_thread(_send)
        return {"recipients": len(notification.email_recipients)}
