"""SQLAlchemy async engine and session management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from src.core.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return the lazily created process-wide async engine."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the lazily created session factory."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Yield a session inside an explicit transaction: commit on success, roll back on error."""
    async with get_sessionmaker()() as session:
        async with session.begin():
            yield session


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI-style dependency yielding a transactional session."""
    async with session_scope() as session:
        yield session


async def dispose_engine() -> None:
    """Close the pooled connections and forget the engine.

    Celery tasks call ``asyncio.run`` per task, and asyncpg connections are bound to the loop that
    created them, so every task must start from a fresh engine.
    """
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = _sessionmaker = None
