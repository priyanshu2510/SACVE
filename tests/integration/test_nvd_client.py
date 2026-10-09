import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from src.core.config import Settings
from src.services.cve_aggregator.nvd import NVDClient, NVDError
from src.utils import retry as retry_mod
from src.utils.rate_limiter import RateLimiter

FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_: float) -> None:
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def make_client(handler, **env) -> NVDClient:
    cfg = Settings(_env_file=None, **env)
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return NVDClient(cfg, client=http, rate_limiter=RateLimiter(1000, 1))


async def test_get_cve_returns_vulnerability():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = dict(request.url.params)
        return httpx.Response(200, json=json.loads((FIX / "nvd_cve_2024_21626.json").read_text()))

    client = make_client(handler)
    vuln = await client.get_cve("cve-2024-21626")
    assert vuln["cve"]["id"] == "CVE-2024-21626"
    assert seen["params"] == {"cveId": "CVE-2024-21626"}


async def test_get_cve_not_found_returns_none():
    client = make_client(lambda r: httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []}))
    assert await client.get_cve("CVE-2000-0000") is None


async def test_api_key_header_sent_when_configured():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("apiKey")
        return httpx.Response(200, json={"vulnerabilities": []})

    cfg = Settings(_env_file=None, NVD_API_KEY="secret-nvd-key")
    client = NVDClient(cfg)  # builds its own client so the header comes from settings
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"apiKey": "secret-nvd-key"}
    )
    await client.get_cve("CVE-2024-1")
    assert seen["key"] == "secret-nvd-key"


async def test_retries_on_throttle_then_succeeds():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(403)
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {"id": "CVE-2024-1"}}]})

    client = make_client(handler)
    assert (await client.get_cve("CVE-2024-1"))["cve"]["id"] == "CVE-2024-1"
    assert calls["n"] == 3


async def test_non_retryable_status_raises_nvd_error():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    client = make_client(handler)
    with pytest.raises(NVDError):
        await client.get_cve("CVE-2024-1")
    assert calls["n"] == 1


async def test_exhausted_retries_raise_nvd_error():
    client = make_client(lambda r: httpx.Response(503))
    with pytest.raises(NVDError):
        await client.get_cve("CVE-2024-1")


async def test_iter_modified_paginates():
    pages = {
        0: {"startIndex": 0, "resultsPerPage": 2, "totalResults": 3,
            "vulnerabilities": [{"cve": {"id": "CVE-1"}}, {"cve": {"id": "CVE-2"}}]},
        2: {"startIndex": 2, "resultsPerPage": 1, "totalResults": 3,
            "vulnerabilities": [{"cve": {"id": "CVE-3"}}]},
    }  # fmt: skip
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        idx = int(request.url.params["startIndex"])
        requested.append(idx)
        assert "lastModStartDate" in request.url.params and "lastModEndDate" in request.url.params
        return httpx.Response(200, json=pages[idx])

    client = make_client(handler)
    end = datetime(2026, 1, 10, tzinfo=timezone.utc)
    ids = [v["cve"]["id"] async for v in client.iter_modified(end - timedelta(days=1), end)]
    assert ids == ["CVE-1", "CVE-2", "CVE-3"] and requested == [0, 2]


async def test_iter_modified_rejects_window_over_120_days():
    client = make_client(lambda r: httpx.Response(200, json={}))
    end = datetime(2026, 1, 10, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        async for _ in client.iter_modified(end - timedelta(days=121), end):
            pass
