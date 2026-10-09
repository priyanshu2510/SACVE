"""Bridge between Celery's synchronous tasks and the async codebase."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from src.agent.deps import reset_deps
from src.core.database import dispose_engine

T = TypeVar("T")


def run_async(fn: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
    """Run ``fn(*args, **kwargs)`` in a fresh event loop and clean up loop-bound resources afterwards.

    The DB engine and the lazily built agent dependencies (HTTP clients, dispatcher) are bound to
    the loop they were created in, so they are discarded when the task finishes.
    """

    async def _wrapped() -> T:
        try:
            return await fn(*args, **kwargs)
        finally:
            await dispose_engine()
            reset_deps()

    return asyncio.run(_wrapped())
