"""Orchestrates NVD + OSV fetching, normalising, merging and storing."""

from __future__ import annotations

import asyncio
import re
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from src.schemas.cve import CVERecord
from src.services.cve_aggregator.normaliser import merge_records, normalise_nvd, normalise_osv
from src.services.cve_aggregator.nvd import NVDClient
from src.services.cve_aggregator.osv import OSVClient
from src.services.cve_aggregator.store import upsert_cve

log = structlog.get_logger(__name__)

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class CVEAggregator:
    """Fetch one CVE from every source, merge by CVE ID, and persist."""

    def __init__(self, nvd: NVDClient, osv: OSVClient) -> None:
        self._nvd = nvd
        self._osv = osv

    async def fetch(self, cve_id: str) -> CVERecord | None:
        """Return the merged record for ``cve_id`` or ``None`` if no source knows it."""
        records: list[CVERecord] = []
        nvd_raw = await self._nvd.get_cve(cve_id)
        if nvd_raw is not None:
            records.append(normalise_nvd(nvd_raw))
        for osv_raw in await self._fetch_osv(cve_id):
            try:
                records.append(normalise_osv(osv_raw, cve_id=cve_id))
            except ValueError as exc:
                log.warning("aggregator.osv_unusable", cve_id=cve_id, error=str(exc))
        if not records:
            log.info("aggregator.not_found", cve_id=cve_id)
            return None
        return merge_records(records)

    async def from_nvd(self, nvd_raw: dict[str, Any]) -> CVERecord:
        """Merge an already-fetched NVD ``vulnerabilities[]`` element with OSV data (saves an NVD call)."""
        record = normalise_nvd(nvd_raw)
        records = [record]
        for osv_raw in await self._fetch_osv(record.cve_id):
            try:
                records.append(normalise_osv(osv_raw, cve_id=record.cve_id))
            except ValueError as exc:
                log.warning("aggregator.osv_unusable", cve_id=record.cve_id, error=str(exc))
        return merge_records(records)

    async def _fetch_osv(self, cve_id: str) -> list[dict[str, Any]]:
        """OSV's CVE record often has only git ranges; package data lives in its GHSA / GO- / PYSEC- aliases."""
        root = await self._osv.get_vuln(cve_id)
        if root is None:
            return []
        alias_ids = [a for a in root.get("aliases", []) if not _CVE_ID.match(a)]
        aliases = await asyncio.gather(*(self._osv.get_vuln(a) for a in alias_ids), return_exceptions=True)
        found = [root]
        for alias_id, result in zip(alias_ids, aliases):
            if isinstance(result, BaseException):
                log.warning("aggregator.osv_alias_failed", cve_id=cve_id, alias=alias_id, error=str(result))
            elif result is not None:
                found.append(result)
        return found

    async def fetch_and_store(self, session: AsyncSession, cve_id: str) -> CVERecord | None:
        """Fetch ``cve_id`` and upsert it inside the caller's transaction."""
        record = await self.fetch(cve_id)
        if record is None:
            return None
        await upsert_cve(session, record)
        log.info(
            "aggregator.stored",
            cve_id=record.cve_id,
            source=record.source,
            packages=len(record.affected_packages),
            severity=record.severity,
        )
        return record
