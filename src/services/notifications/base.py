"""Notification primitives: the message, the per-channel result and the handler ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from src.core.config import settings

EVENTS = ("CVE_DETECTED", "PR_RAISED", "PR_MERGED", "ESCALATED")


@dataclass(frozen=True)
class Notification:
    """A message about one CVE/repo job, fanned out to every enabled channel."""

    event: str
    job_id: str
    cve_id: str
    repo_name: str
    severity: str
    subject: str
    body: str
    recipients: list[str] = field(default_factory=list)  # emails, "@user" handles or "@org/team"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def email_recipients(self) -> list[str]:
        """Recipients that are real email addresses."""
        return [r for r in self.recipients if "@" in r and not r.startswith("@")]


@dataclass
class NotificationResult:
    """What happened on one channel."""

    channel: str
    status: str  # sent | failed | skipped
    response: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class NotificationHandler(ABC):
    """One notification channel. Implementations raise on delivery failure; the dispatcher handles it."""

    name: str

    def supports(self, notification: Notification) -> bool:
        """Whether this channel should receive ``notification`` (default: every event)."""
        return True

    @abstractmethod
    async def send(self, notification: Notification) -> dict[str, Any]:
        """Deliver the notification and return a small response summary (never secrets)."""


def resolve_recipients(owners: list[str]) -> list[str]:
    """Map CODEOWNERS entries to notification recipients.

    Emails pass through. ``@user`` becomes ``user@OWNER_EMAIL_DOMAIN`` when that is configured,
    otherwise it stays ``@user`` for the Teams API to resolve. Teams stay ``@org/team``.
    """
    domain = settings.OWNER_EMAIL_DOMAIN
    out: dict[str, str] = {}
    for owner in owners:
        if owner.startswith("@") and "/" not in owner and domain:
            owner = f"{owner[1:]}@{domain}"
        out.setdefault(owner.lower(), owner)
    return list(out.values())
