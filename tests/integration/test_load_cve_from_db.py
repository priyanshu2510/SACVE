import json
from pathlib import Path

import pytest

from src.agent.deps import load_cve_from_db
from src.core.database import session_scope
from src.services.cve_aggregator.normaliser import merge_records, normalise_osv
from src.services.cve_aggregator.store import upsert_cve

pytestmark = pytest.mark.db
FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
async def seeded(migrated_db):
    import src.core.database as dbmod

    dbmod._engine = dbmod._sessionmaker = None  # rebuild against the scratch DB
    recs = [normalise_osv(json.loads((FIX / n).read_text())) for n in ("osv_ghsa_xr7r_f8xq_vfvv.json",)]
    multi = normalise_osv(json.loads((FIX / "osv_pypi_multi_branch.json").read_text()))
    async with session_scope() as s:
        await upsert_cve(s, merge_records(recs))
        await upsert_cve(s, multi)
    yield
    await dbmod.get_engine().dispose()
    dbmod._engine = dbmod._sessionmaker = None


async def test_loads_package_facts(seeded):
    ctx = await load_cve_from_db("CVE-2024-21626", "go", "github.com/opencontainers/runc")
    assert ctx.fixed_version == "1.1.12" and ctx.fixed_versions == ["1.1.12"]
    assert ctx.affected_versions == [">= 0.0.0-rc93, < 1.1.12"] and ctx.description


async def test_multi_branch_fixes_all_listed(seeded):
    ctx = await load_cve_from_db("CVE-2099-0001", "pip", "ExamplePkg")  # pip names compare PEP 503-normalised
    assert ctx.fixed_versions == ["1.4.9", "2.0.3"]


async def test_unknown_package_returns_cve_without_fixes(seeded):
    ctx = await load_cve_from_db("CVE-2024-21626", "go", "github.com/other/pkg")
    assert ctx is not None and ctx.fixed_versions == []


async def test_unknown_cve_returns_none(seeded):
    assert await load_cve_from_db("CVE-1999-0001", "pip", "x") is None
