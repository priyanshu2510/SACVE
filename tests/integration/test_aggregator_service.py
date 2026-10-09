import json
from pathlib import Path

import httpx

from src.core.config import Settings
from src.services.cve_aggregator.nvd import NVDClient
from src.services.cve_aggregator.osv import OSVClient
from src.services.cve_aggregator.service import CVEAggregator
from src.utils.rate_limiter import RateLimiter

FIX = Path(__file__).resolve().parents[1] / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


def build(osv_routes: dict[str, httpx.Response], nvd_body=None) -> CVEAggregator:
    cfg = Settings(_env_file=None)

    def osv(request: httpx.Request) -> httpx.Response:
        return osv_routes.get(request.url.path.rsplit("/", 1)[-1], httpx.Response(404))

    nvd_http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=nvd_body or {"vulnerabilities": []}))
    )
    return CVEAggregator(
        NVDClient(cfg, client=nvd_http, rate_limiter=RateLimiter(1000, 1)),
        OSVClient(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(osv))),
    )


async def test_follows_osv_aliases_to_find_package_data():
    """Real OSV shape: the CVE record has only GIT ranges, the GHSA alias has the Go module."""
    agg = build(
        {
            "CVE-2024-21626": httpx.Response(200, json=load("osv_cve_2024_21626_root.json")),
            "GHSA-xr7r-f8xq-vfvv": httpx.Response(200, json=load("osv_ghsa_xr7r_f8xq_vfvv.json")),
            "GO-2024-2491": httpx.Response(404),  # a missing alias must not break the merge
        },
        nvd_body=load("nvd_cve_2024_21626.json"),
    )
    rec = await agg.fetch("CVE-2024-21626")
    assert rec.source == "NVD+OSV" and rec.cvss_v3_score == 8.6
    (pkg,) = rec.affected_packages
    assert (pkg.ecosystem.value, pkg.package_name, pkg.fixed_version) == ("go", "github.com/opencontainers/runc", "1.1.12")
    assert len(rec.raw_data["osv"]) == 2  # root + GHSA


async def test_alias_failure_is_tolerated():
    agg = build(
        {
            "CVE-2024-21626": httpx.Response(200, json=load("osv_cve_2024_21626_root.json")),
            "GHSA-xr7r-f8xq-vfvv": httpx.Response(500),
        }
    )
    import src.utils.retry as retry_mod

    async def _sleep(_):
        return None

    real, retry_mod.asyncio.sleep = retry_mod.asyncio.sleep, _sleep
    try:
        rec = await agg.fetch("CVE-2024-21626")
    finally:
        retry_mod.asyncio.sleep = real
    assert rec is not None and rec.affected_packages == []
