"""Live smoke test: fetch one CVE from NVD + OSV, merge, store, and print the stored row.

    python -m scripts.smoke_aggregate CVE-2024-21626

Read-only against the public APIs; writes to the database in DATABASE_URL (run ``alembic upgrade head`` first).
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select

from src.core.database import get_engine, session_scope
from src.core.logging import configure_logging
from src.models.cve import CVE, CVEAffectedPackage
from src.services.cve_aggregator.nvd import NVDClient
from src.services.cve_aggregator.osv import OSVClient
from src.services.cve_aggregator.service import CVEAggregator


async def main(cve_id: str) -> int:
    """Aggregate ``cve_id`` and print what was stored; returns a process exit code."""
    configure_logging("WARNING")
    async with NVDClient() as nvd, OSVClient() as osv:
        async with session_scope() as session:
            record = await CVEAggregator(nvd, osv).fetch_and_store(session, cve_id)
    if record is None:
        print(f"{cve_id}: not found in NVD or OSV")
        return 1
    async with session_scope() as session:
        cve = (await session.execute(select(CVE).where(CVE.cve_id == record.cve_id))).scalar_one()
        pkgs = (await session.execute(select(CVEAffectedPackage).where(CVEAffectedPackage.cve_id == cve.cve_id))).scalars().all()
    print(f"{cve.cve_id}  source={cve.source}  cvss={cve.cvss_v3_score}  severity={cve.severity}  kev={cve.cisa_kev}")
    print(f"title: {cve.title}")
    for p in pkgs:
        print(f"  [{p.ecosystem}] {p.package_name}  fixed={p.fixed_version}  ranges={p.affected_versions}")
    await get_engine().dispose()
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(asyncio.run(main(sys.argv[1])))
