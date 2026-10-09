"""Persist normalised CVE records and raw feed responses (one transaction per call)."""

from __future__ import annotations

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.redaction import redact_obj
from src.models.cve import CVE, CVEAffectedPackage, CVERawFeed
from src.schemas.cve import CVERecord


async def upsert_cve(session: AsyncSession, record: CVERecord) -> None:
    """Upsert ``record`` (keyed on ``cve_id``), replace its affected packages, append raw feeds.

    The caller owns the transaction (see ``session_scope``).
    """
    values = {
        "cve_id": record.cve_id,
        "title": record.title,
        "description": record.description,
        "cvss_v3_score": record.cvss_v3_score,
        "cvss_v3_vector": record.cvss_v3_vector,
        "severity": record.severity,
        "cisa_kev": record.cisa_kev,
        "published_at": record.published_at,
        "source": record.source,
        "raw_data": redact_obj(record.raw_data),
    }
    stmt = pg_insert(CVE).values(**values)
    update_cols = {k: stmt.excluded[k] for k in values if k != "cve_id"}
    await session.execute(stmt.on_conflict_do_update(index_elements=[CVE.cve_id], set_=update_cols))

    await session.execute(delete(CVEAffectedPackage).where(CVEAffectedPackage.cve_id == record.cve_id))
    session.add_all(
        CVEAffectedPackage(
            cve_id=record.cve_id,
            ecosystem=pkg.ecosystem.value,
            package_name=pkg.package_name,
            affected_versions=pkg.affected_versions,
            fixed_version=pkg.fixed_version,
        )
        for pkg in record.affected_packages
    )
    for source, payload in record.raw_data.items():
        session.add(
            CVERawFeed(
                cve_id=record.cve_id,
                source=source.upper(),
                payload=redact_obj({"data": payload}),
            )
        )
    await session.flush()
