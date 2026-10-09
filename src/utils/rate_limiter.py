"""Async sliding-window rate limiter (N calls per period)."""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    """Allow at most ``max_calls`` acquisitions per ``period`` seconds."""

    def __init__(self, max_calls: int, period: float) -> None:
        if max_calls < 1 or period <= 0:
            raise ValueError("max_calls must be >= 1 and period > 0")
        self._max_calls = max_calls
        self._period = period
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a call slot is available, then claim it."""
        async with self._lock:
            while True:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self._period:
                    self._calls.popleft()
                if len(self._calls) < self._max_calls:
                    self._calls.append(now)
                    return
                await asyncio.sleep(self._period - (now - self._calls[0]))
