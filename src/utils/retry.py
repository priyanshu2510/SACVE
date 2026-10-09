"""Async retry decorator: exponential backoff with full jitter."""

from __future__ import annotations

import asyncio
import functools
import random
from collections.abc import Awaitable, Callable
from typing import ParamSpec, TypeVar

import structlog

log = structlog.get_logger(__name__)

P = ParamSpec("P")
T = TypeVar("T")


def retry_async(
    *,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    is_retryable: Callable[[BaseException], bool] | None = None,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Retry an async function up to ``max_retries`` times after the first attempt.

    Delay before retry ``n`` (0-based) is ``uniform(0, min(max_delay, base_delay * 2**n))``.
    Exceptions not in ``retry_on`` (or rejected by ``is_retryable``) propagate immediately.
    The final failure is logged with context and re-raised.
    """

    def decorator(fn: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            attempt = 0
            while True:
                try:
                    return await fn(*args, **kwargs)
                except retry_on as exc:
                    retryable = is_retryable(exc) if is_retryable else True
                    if not retryable or attempt >= max_retries:
                        log.error(
                            "retry.exhausted",
                            fn=fn.__qualname__,
                            attempts=attempt + 1,
                            error=str(exc),
                        )
                        raise
                    delay = random.uniform(0, min(max_delay, base_delay * (2**attempt)))
                    log.warning(
                        "retry.backoff",
                        fn=fn.__qualname__,
                        attempt=attempt + 1,
                        delay_s=round(delay, 3),
                        error=str(exc),
                    )
                    await asyncio.sleep(delay)
                    attempt += 1

        return wrapper

    return decorator
