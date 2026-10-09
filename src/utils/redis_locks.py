"""Redis-backed coordination primitives: a mutual-exclusion lock and a counting semaphore with leases."""

from __future__ import annotations

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import redis.asyncio as aioredis

_RELEASE_LOCK = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end
"""

# Atomically: drop expired leases, then add ours if there is room.
_ACQUIRE_SLOT = """
redis.call('zremrangebyscore', KEYS[1], '-inf', ARGV[1])
if redis.call('zcard', KEYS[1]) < tonumber(ARGV[2]) then
  redis.call('zadd', KEYS[1], ARGV[3], ARGV[4])
  return 1
end
return 0
"""


class LockBusyError(RuntimeError):
    """The lock is held by someone else."""


class RedisLock:
    """A non-reentrant lock with a TTL, safe against releasing someone else's lock."""

    def __init__(self, client: aioredis.Redis, key: str, ttl_seconds: int) -> None:
        self._r, self.key, self._ttl = client, key, ttl_seconds
        self._token = uuid.uuid4().hex
        self._held = False

    async def acquire(self) -> bool:
        """Try once; returns whether the lock is now held by us."""
        self._held = bool(await self._r.set(self.key, self._token, nx=True, ex=self._ttl))
        return self._held

    async def release(self) -> None:
        """Release only if we still own it (the TTL may have expired and someone else taken it)."""
        if self._held:
            await self._r.eval(_RELEASE_LOCK, 1, self.key, self._token)
            self._held = False


@asynccontextmanager
async def repo_lock(client: aioredis.Redis, repo_name: str, ttl_seconds: int) -> AsyncIterator[None]:
    """Serialise work per repository; raises :class:`LockBusyError` immediately if it is taken."""
    lock = RedisLock(client, f"cve-remediation:repo-lock:{repo_name.lower()}", ttl_seconds)
    if not await lock.acquire():
        raise LockBusyError(f"{repo_name} is being processed by another job")
    try:
        yield
    finally:
        await lock.release()


class RedisSemaphore:
    """Counting semaphore shared by all workers. Holders lease a slot, so a crashed worker's slot expires."""

    def __init__(self, client: aioredis.Redis, key: str, limit: int, lease_seconds: int) -> None:
        self._r, self._key, self._limit, self._lease = client, key, limit, lease_seconds

    async def try_acquire(self, holder: str) -> bool:
        """Take a slot for ``holder`` if one is free."""
        now = time.time()
        got = await self._r.eval(_ACQUIRE_SLOT, 1, self._key, now, self._limit, now + self._lease, holder)
        return bool(got)

    async def acquire(self, holder: str, poll_seconds: float = 1.0) -> None:
        """Wait until a slot is available."""
        while not await self.try_acquire(holder):
            await asyncio.sleep(poll_seconds)

    async def release(self, holder: str) -> None:
        """Give the slot back (idempotent)."""
        await self._r.zrem(self._key, holder)

    async def count(self) -> int:
        """Number of live leases."""
        await self._r.zremrangebyscore(self._key, "-inf", time.time())
        return int(await self._r.zcard(self._key))
