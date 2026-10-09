"""Store + aggregator against real Postgres (scratch DB with migrations applied). Skipped if unreachable."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.core.config import Settings, settings
from src.models.cve import CVE, CVEAffectedPackage, CVERawFeed
from src.services.cve_aggregator.normaliser import merge_records, normalise_nvd, normalise_osv
from src.services.cve_aggregator.nvd import NVDClient
from src.services.cve_aggregator.osv import OSVClient
from src.services.cve_aggregator.service import CVEAggregator
from src.services.cve_aggregator.store import upsert_cve
from src.utils.rate_limiter import RateLimiter

pytestmark = pytest.mark.db
FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
async def session_factory(migrated_db):
    engine = create_async_engine(settings.DATABASE_URL)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


def _record():
    nvd = normalise_nvd(json.loads((FIX / "nvd_cve_2024_21626.json").read_text())["vulnerabilities"][0])
    osv = normalise_osv(json.loads((FIX / "osv_ghsa_xr7r_f8xq_vfvv.json").read_text()))
    return merge_records([nvd, osv])


async def test_upsert_is_idempotent_and_replaces_packages(session_factory):
    record = _record()
    async with session_factory() as s, s.begin():
        await upsert_cve(s, record)
    record.affected_packages[0].fixed_version = "1.1.13"
    record.cvss_v3_score = 9.1
    async with session_factory() as s, s.begin():
        await upsert_cve(s, record)

    async with session_factory() as s:
        cve = (await s.execute(select(CVE).where(CVE.cve_id == "CVE-2024-21626"))).scalar_one()
        pkgs = (await s.execute(select(CVEAffectedPackage))).scalars().all()
        feeds = (await s.execute(select(func.count()).select_from(CVERawFeed))).scalar_one()
    assert cve.cvss_v3_score == 9.1 and cve.cisa_kev is True and cve.source == "NVD+OSV"
    assert [(p.ecosystem, p.package_name, p.fixed_version) for p in pkgs] == [
        ("go", "github.com/opencontainers/runc", "1.1.13")
    ]
    assert feeds == 4  # raw feed history is append-only: 2 sources x 2 upserts


async def test_aggregator_fetch_and_store_with_mocked_sources(session_factory):
    def nvd_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=json.loads((FIX / "nvd_cve_2024_21626.json").read_text()))

    def osv_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=json.loads((FIX / "osv_ghsa_xr7r_f8xq_vfvv.json").read_text()))

    cfg = Settings(_env_file=None)
    nvd = NVDClient(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(nvd_handler)),
                    rate_limiter=RateLimiter(1000, 1))  # fmt: skip
    osv = OSVClient(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(osv_handler)))
    agg = CVEAggregator(nvd, osv)
    async with session_factory() as s, s.begin():
        rec = await agg.fetch_and_store(s, "CVE-2024-21626")
    assert rec is not None and rec.source == "NVD+OSV"
    async with session_factory() as s:
        assert (await s.get(CVE, "CVE-2024-21626")).severity == "HIGH"


async def test_aggregator_returns_none_when_unknown():
    cfg = Settings(_env_file=None)
    nvd = NVDClient(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"vulnerabilities": []}))), rate_limiter=RateLimiter(1000, 1))  # fmt: skip
    osv = OSVClient(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))))
    assert await CVEAggregator(nvd, osv).fetch("CVE-2000-0000") is None
