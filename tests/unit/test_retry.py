import pytest

from src.utils import retry as retry_mod
from src.utils.retry import retry_async


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_: float) -> None:
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


async def test_succeeds_after_transient_failures():
    calls = {"n": 0}

    @retry_async(max_retries=3)
    async def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("boom")
        return "ok"

    assert await flaky() == "ok"
    assert calls["n"] == 3


async def test_reraises_after_max_retries():
    calls = {"n": 0}

    @retry_async(max_retries=2)
    async def always() -> None:
        calls["n"] += 1
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError):
        await always()
    assert calls["n"] == 3  # first attempt + 2 retries


async def test_non_retryable_propagates_immediately():
    calls = {"n": 0}

    @retry_async(max_retries=3, is_retryable=lambda e: not isinstance(e, KeyError))
    async def fn() -> None:
        calls["n"] += 1
        raise KeyError("x")

    with pytest.raises(KeyError):
        await fn()
    assert calls["n"] == 1


async def test_retry_on_filters_exception_types():
    @retry_async(max_retries=3, retry_on=(ValueError,))
    async def fn() -> None:
        raise TypeError("not retried")

    with pytest.raises(TypeError):
        await fn()
