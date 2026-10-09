"""Injectable dependencies for graph nodes.

LangGraph fixes the node signature to ``(state) -> dict``, so external collaborators
(GitHub, CVE database, LLM transport) are resolved through this small holder. Production
uses lazily built defaults; tests call :func:`override_deps`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

import httpx
from pydantic import BaseModel, Field

from src.services.audit.store import AuditStore
from src.services.github.client import GitHubContentSource
from src.services.github.pr_creator import PullRequestService
from src.services.idempotency import IdempotencyStore
from src.services.notifications.dispatcher import NotificationDispatcher
from src.services.sandbox.base import SandboxManager


class CVEContext(BaseModel):
    """CVE facts for one (ecosystem, package) pair, as stored in the database."""

    cve_id: str
    title: str | None = None
    description: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    fixed_version: str | None = None  # lowest advisory fix
    fixed_versions: list[str] = Field(default_factory=list)  # every advisory fix (per-branch)


CVELoader = Callable[[str, str, str], Awaitable[CVEContext | None]]  # (cve_id, ecosystem, package)
PostAuditHook = Callable[[str], Awaitable[None]]  # called with job_id after the audit trail is flushed
ThresholdLoader = Callable[[], Awaitable[tuple[int, int]]]  # calibrated (high, medium) confidence tier cut-offs


@dataclass
class AgentDeps:
    """Collaborators used by nodes. ``None`` fields are built lazily from settings."""

    content_source: GitHubContentSource | None = None
    cve_loader: CVELoader | None = None
    llm_transport: httpx.AsyncBaseTransport | None = None
    sandbox_manager: SandboxManager | None = None
    pr_service: PullRequestService | None = None
    idempotency: IdempotencyStore | None = None
    audit_store: AuditStore | None = None
    dispatcher: NotificationDispatcher | None = None
    post_audit_hook: PostAuditHook | None = None
    tier_thresholds: ThresholdLoader | None = None
    _built: dict[str, object] = field(default_factory=dict, repr=False)


_deps = AgentDeps()


def reset_deps() -> None:
    """Drop lazily built collaborators (their HTTP clients are bound to a finished event loop)."""
    global _deps
    _deps = AgentDeps()


def get_content_source() -> GitHubContentSource:
    """Return the configured GitHub content source (PyGithub by default)."""
    if _deps.content_source is None:
        from src.services.github.client import PyGithubContentSource

        _deps.content_source = PyGithubContentSource()
    return _deps.content_source


def get_cve_loader() -> CVELoader:
    """Return the configured CVE loader (database-backed by default)."""
    return _deps.cve_loader or load_cve_from_db


def get_sandbox_manager() -> SandboxManager:
    """Return the configured sandbox manager (Docker by default)."""
    if _deps.sandbox_manager is None:
        from src.core.config import settings
        from src.services.sandbox.docker_sandbox import DockerSandboxManager, RedisSlotLimiter

        slots = None
        if settings.SANDBOX_SLOTS_BACKEND == "redis":
            import redis.asyncio as aioredis

            from src.utils.redis_locks import RedisSemaphore

            semaphore = RedisSemaphore(
                aioredis.from_url(settings.REDIS_URL), "cve-remediation:sandbox-slots",
                settings.MAX_CONCURRENT_SANDBOXES, settings.SANDBOX_SLOT_LEASE_SECONDS,
            )  # fmt: skip
            slots = RedisSlotLimiter(semaphore)
        _deps.sandbox_manager = DockerSandboxManager(slots=slots)
    return _deps.sandbox_manager


def get_pr_service() -> PullRequestService:
    """Return the configured pull-request service (PyGithub by default)."""
    if _deps.pr_service is None:
        from src.services.github.pr_creator import PyGithubPullRequestService

        _deps.pr_service = PyGithubPullRequestService()
    return _deps.pr_service


def get_idempotency_store() -> IdempotencyStore:
    """Return the idempotency store (PostgreSQL by default)."""
    if _deps.idempotency is None:
        from src.services.idempotency import DbIdempotencyStore

        _deps.idempotency = DbIdempotencyStore()
    return _deps.idempotency


def get_audit_store() -> AuditStore:
    """Return the audit store (PostgreSQL by default)."""
    if _deps.audit_store is None:
        from src.services.audit.store import DbAuditStore

        _deps.audit_store = DbAuditStore()
    return _deps.audit_store


def get_dispatcher() -> NotificationDispatcher:
    """Return the notification dispatcher built from ``ENABLED_NOTIFICATION_CHANNELS``."""
    if _deps.dispatcher is None:
        from src.services.notifications.dispatcher import NotificationDispatcher, build_handlers
        from src.services.notifications.log_store import DbNotificationLogStore

        _deps.dispatcher = NotificationDispatcher(build_handlers(), get_idempotency_store(), DbNotificationLogStore())
    return _deps.dispatcher


def get_tier_thresholds() -> ThresholdLoader:
    """Loader for the calibrated confidence-tier cut-offs (database-backed by default)."""

    async def _from_db() -> tuple[int, int]:
        from src.core.database import session_scope
        from src.services.calibration import load_thresholds

        async with session_scope() as session:
            return await load_thresholds(session)

    return _deps.tier_thresholds or _from_db


def get_post_audit_hook() -> PostAuditHook:
    """Hook run after the audit flush: queues the Confluence/JIRA sync (``audit.sync_tracking``)."""

    async def _enqueue(job_id: str) -> None:
        from src.workers.tasks.audit_tasks import enqueue_tracking_sync

        enqueue_tracking_sync(job_id)

    return _deps.post_audit_hook or _enqueue


def get_llm_transport() -> httpx.AsyncBaseTransport | None:
    """Return the injected LLM transport, or ``None`` to use the network."""
    return _deps.llm_transport


@contextmanager
def override_deps(
    *,
    content_source: GitHubContentSource | None = None,
    cve_loader: CVELoader | None = None,
    llm_transport: httpx.AsyncBaseTransport | None = None,
    sandbox_manager: SandboxManager | None = None,
    pr_service: PullRequestService | None = None,
    idempotency: IdempotencyStore | None = None,
    audit_store: AuditStore | None = None,
    dispatcher: NotificationDispatcher | None = None,
    post_audit_hook: PostAuditHook | None = None,
    tier_thresholds: ThresholdLoader | None = None,
) -> Iterator[None]:
    """Temporarily replace collaborators (tests, local experiments)."""
    global _deps
    previous = _deps
    _deps = AgentDeps(
        content_source=content_source or previous.content_source,
        cve_loader=cve_loader or previous.cve_loader,
        llm_transport=llm_transport or previous.llm_transport,
        sandbox_manager=sandbox_manager or previous.sandbox_manager,
        pr_service=pr_service or previous.pr_service,
        idempotency=idempotency or previous.idempotency,
        audit_store=audit_store or previous.audit_store,
        dispatcher=dispatcher or previous.dispatcher,
        post_audit_hook=post_audit_hook or previous.post_audit_hook,
        tier_thresholds=tier_thresholds or previous.tier_thresholds,
    )
    try:
        yield
    finally:
        _deps = previous


def fixed_versions_from_ranges(affected_versions: list[str], fixed_version: str | None) -> list[str]:
    """All fix versions implied by range strings like ``">= 2.0.0, < 2.0.3"`` plus ``fixed_version``."""
    import re

    found = [m for s in affected_versions for m in re.findall(r"(?<![<>=])<(?!=)\s*([^\s,]+)", s)]
    if fixed_version:
        found.append(fixed_version)
    return list(dict.fromkeys(found))


async def load_cve_from_db(cve_id: str, ecosystem: str, package: str) -> CVEContext | None:
    """Load CVE facts for ``package`` from PostgreSQL (``None`` if the CVE or package is unknown)."""
    from sqlalchemy import select

    from src.core.database import session_scope
    from src.models.cve import CVE, CVEAffectedPackage
    from src.utils.packages import normalise_pip_name

    async with session_scope() as session:
        cve = await session.get(CVE, cve_id)
        if cve is None:
            return None
        rows = (
            await session.execute(
                select(CVEAffectedPackage).where(
                    CVEAffectedPackage.cve_id == cve_id, CVEAffectedPackage.ecosystem == ecosystem
                )
            )
        ).scalars().all()
    norm = (lambda n: normalise_pip_name(n)) if ecosystem == "pip" else (lambda n: n)
    match = next((r for r in rows if norm(r.package_name) == norm(package)), None)
    if match is None:
        return CVEContext(cve_id=cve_id, title=cve.title, description=cve.description)
    return CVEContext(
        cve_id=cve_id,
        title=cve.title,
        description=cve.description,
        affected_versions=list(match.affected_versions),
        fixed_version=match.fixed_version,
        fixed_versions=fixed_versions_from_ranges(list(match.affected_versions), match.fixed_version),
    )
