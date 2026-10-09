import json
from pathlib import Path

import httpx
import pytest

from src.core.config import Settings
from src.services.cve_aggregator.osv import OSVClient, OSVError
from src.utils import retry as retry_mod

FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_: float) -> None:
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def make_client(handler) -> OSVClient:
    return OSVClient(Settings(_env_file=None), client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


async def test_get_vuln():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json=json.loads((FIX / "osv_ghsa_xr7r_f8xq_vfvv.json").read_text()))

    vuln = await make_client(handler).get_vuln("GHSA-xr7r-f8xq-vfvv")
    assert vuln["aliases"] == ["CVE-2024-21626"] and seen["path"] == "/v1/vulns/GHSA-xr7r-f8xq-vfvv"


async def test_get_vuln_404_is_none():
    assert await make_client(lambda r: httpx.Response(404, json={"code": 5})).get_vuln("CVE-2000-1") is None


async def test_get_vuln_server_error_raises():
    with pytest.raises(OSVError):
        await make_client(lambda r: httpx.Response(500)).get_vuln("CVE-2000-1")


async def test_query_package_follows_pagination():
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        if "page_token" not in body:
            return httpx.Response(200, json={"vulns": [{"id": "A"}], "next_page_token": "t1"})
        return httpx.Response(200, json={"vulns": [{"id": "B"}]})

    vulns = await make_client(handler).query_package("PyPI", "requests", "2.0.0")
    assert [v["id"] for v in vulns] == ["A", "B"]
    assert bodies[0] == {"package": {"ecosystem": "PyPI", "name": "requests"}, "version": "2.0.0"}
    assert bodies[1]["page_token"] == "t1"


async def test_retries_transport_errors():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("boom")
        return httpx.Response(200, json={"vulns": []})

    assert await make_client(handler).query_package("npm", "left-pad") == []
    assert calls["n"] == 2
