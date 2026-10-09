import pytest

from src.utils import rate_limiter as rl
from src.utils.rate_limiter import RateLimiter


async def test_blocks_after_burst_until_window_passes(monkeypatch):
    now = {"t": 100.0}
    slept: list[float] = []

    async def fake_sleep(d: float) -> None:
        slept.append(d)
        now["t"] += d

    monkeypatch.setattr(rl.time, "monotonic", lambda: now["t"])
    monkeypatch.setattr(rl.asyncio, "sleep", fake_sleep)
    limiter = RateLimiter(2, 10.0)
    for _ in range(2):
        await limiter.acquire()
    assert slept == []
    await limiter.acquire()  # third call must wait for the first slot to expire
    assert slept == [pytest.approx(10.0)]


def test_rejects_bad_config():
    with pytest.raises(ValueError):
        RateLimiter(0, 1)
    with pytest.raises(ValueError):
        RateLimiter(1, 0)
