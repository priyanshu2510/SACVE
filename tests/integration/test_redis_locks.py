import asyncio

import pytest
import redis.asyncio as aioredis

from src.core.config import settings
from src.utils.redis_locks import LockBusyError, RedisLock, RedisSemaphore, repo_lock

pytestmark = pytest.mark.redis


@pytest.fixture
async def r():
    client = aioredis.from_url(settings.REDIS_URL.rsplit("/", 1)[0] + "/13")  # scratch db
    try:
        await client.ping()
    except Exception:
        pytest.skip("Redis not reachable")
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


async def test_lock_is_exclusive_and_released(r):
    a, b = RedisLock(r, "k", 30), RedisLock(r, "k", 30)
    assert await a.acquire() and not await b.acquire()
    await a.release()
    assert await b.acquire()


async def test_release_never_frees_someone_elses_lock(r):
    a = RedisLock(r, "k", 1)
    assert await a.acquire()
    await asyncio.sleep(1.2)  # a's TTL expired...
    b = RedisLock(r, "k", 30)
    assert await b.acquire()  # ...b took over
    await a.release()  # a (late) must not delete b's lock
    assert await r.get("k") is not None
    await b.release()
    assert await r.get("k") is None


async def test_repo_lock_serialises_per_repo_case_insensitively(r):
    async with repo_lock(r, "Org/Api", 30):
        with pytest.raises(LockBusyError):
            async with repo_lock(r, "org/api", 30):
                pass
        async with repo_lock(r, "org/other", 30):  # different repo is independent
            pass
    async with repo_lock(r, "org/api", 30):  # released on exit
        pass


async def test_repo_lock_released_when_the_body_raises(r):
    with pytest.raises(RuntimeError):
        async with repo_lock(r, "org/api", 30):
            raise RuntimeError("job crashed")
    async with repo_lock(r, "org/api", 30):
        pass


async def test_semaphore_caps_concurrency_across_clients(r):
    other = aioredis.from_url(settings.REDIS_URL.rsplit("/", 1)[0] + "/13")  # a second "worker"
    try:
        sem1, sem2 = RedisSemaphore(r, "slots", 2, 60), RedisSemaphore(other, "slots", 2, 60)
        assert await sem1.try_acquire("a") and await sem2.try_acquire("b")
        assert not await sem1.try_acquire("c") and not await sem2.try_acquire("c")
        assert await sem1.count() == 2
        await sem2.release("a")
        assert await sem1.try_acquire("c") and await sem1.count() == 2
        await sem1.release("zzz")  # unknown holder: harmless
    finally:
        await other.aclose()


async def test_crashed_holder_slot_expires(r):
    sem = RedisSemaphore(r, "slots", 1, lease_seconds=1)
    assert await sem.try_acquire("crashed-worker")
    assert not await sem.try_acquire("next")
    await asyncio.sleep(1.2)
    assert await sem.try_acquire("next")  # the lease lapsed


async def test_acquire_waits_for_a_free_slot(r):
    sem = RedisSemaphore(r, "slots", 1, 60)
    await sem.acquire("first")
    waiter = asyncio.create_task(sem.acquire("second", poll_seconds=0.05))
    await asyncio.sleep(0.3)
    assert not waiter.done()
    await sem.release("first")
    await asyncio.wait_for(waiter, 2)
