"""Check-before-create guard for external side effects (PRs, notifications, audit flushes)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.core.database import session_scope
from src.models.job import IdempotencyKey


@runtime_checkable
class IdempotencyStore(Protocol):
    """Remembers the result of a side effect keyed by a deterministic key (derived from ``job_id``)."""

    async def get(self, key: str) -> dict[str, Any] | None:
        """Return the recorded result for ``key`` or ``None``."""

    async def put(self, key: str, scope: str, result: dict[str, Any]) -> None:
        """Record ``result`` for ``key``; a second put for the same key is ignored."""


class DbIdempotencyStore:
    """PostgreSQL-backed store (table ``idempotency_keys``)."""

    async def get(self, key: str) -> dict[str, Any] | None:
        """Return the stored result for ``key``."""
        async with session_scope() as session:
            row = await session.get(IdempotencyKey, key)
            return dict(row.result) if row else None

    async def put(self, key: str, scope: str, result: dict[str, Any]) -> None:
        """Insert ``key`` unless it already exists."""
        async with session_scope() as session:
            stmt = pg_insert(IdempotencyKey).values(key=key, scope=scope, result=result)
            await session.execute(stmt.on_conflict_do_nothing(index_elements=[IdempotencyKey.key]))
