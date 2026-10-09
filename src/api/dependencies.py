"""FastAPI dependencies: authentication, IP allowlist, DB session, and the injectable back-ends."""

from __future__ import annotations

import hmac
import ipaddress
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Callable

from fastapi import Depends, Header, HTTPException, Request
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy.ext.asyncio import AsyncSession

from src.agent.graph import build_fix_agent_graph
from src.core.config import settings
from src.core.database import session_scope
from src.services.task_queue import CeleryTaskQueue, TaskQueue

GraphFactory = Callable[[], AbstractAsyncContextManager[Any]]  # async context manager yielding a compiled graph


def ip_allowed(client_host: str | None, allowlist: list[str]) -> bool:
    """True if the allowlist is empty or ``client_host`` is inside one of its IPs / CIDRs."""
    if not allowlist:
        return True
    try:
        addr = ipaddress.ip_address(client_host or "")
    except ValueError:
        return False
    for entry in allowlist:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def check_ip(request: Request) -> None:
    """Reject callers outside ``CONTROL_API_IP_ALLOWLIST`` (the TCP peer; put a trusted proxy's CIDR in the list)."""
    if not ip_allowed(request.client.host if request.client else None, settings.CONTROL_API_IP_ALLOWLIST):
        raise HTTPException(403, "client address is not allowed")


async def require_api_key(request: Request, x_api_key: str | None = Header(default=None)) -> None:
    """Authenticate with the ``X-API-Key`` header. Fails closed when no key is configured."""
    check_ip(request)
    expected = settings.API_KEY.get_secret_value() if settings.API_KEY else ""
    if not expected:
        raise HTTPException(503, "API key is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(401, "invalid or missing API key", headers={"WWW-Authenticate": "ApiKey"})


async def get_session() -> AsyncIterator[AsyncSession]:
    """A transactional session: commits when the request succeeds, rolls back on error."""
    async with session_scope() as session:
        yield session


_queue: TaskQueue | None = None


def get_queue() -> TaskQueue:
    """The Celery-backed task queue (overridden in tests)."""
    global _queue
    if _queue is None:
        _queue = CeleryTaskQueue()
    return _queue


@asynccontextmanager
async def _postgres_graph() -> AsyncIterator[Any]:
    async with AsyncPostgresSaver.from_conn_string(settings.checkpoint_database_url) as saver:
        yield build_fix_agent_graph(saver)


def get_graph_factory() -> GraphFactory:
    """Factory of a compiled graph bound to the PostgreSQL checkpointer (for reading history)."""
    return _postgres_graph


Authed = [Depends(require_api_key)]
