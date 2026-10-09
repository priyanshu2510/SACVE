"""Normalise raw NVD / OSV payloads into :class:`CVERecord` and merge them (keyed on CVE ID)."""

from __future__ import annotations

import functools
import re
from datetime import datetime, timezone
from typing import Any

import structlog

from src.schemas.cve import AffectedPackage, CVERecord, Ecosystem
from src.utils.version_compare import compare_versions

log = structlog.get_logger(__name__)

_OSV_ECOSYSTEMS: dict[str, Ecosystem] = {
    "pypi": Ecosystem.PIP,
    "npm": Ecosystem.NPM,
    "maven": Ecosystem.MAVEN,
    "go": Ecosystem.GO,
    "nuget": Ecosystem.NUGET,
    "rubygems": Ecosystem.GEM,
}
_version_sort_key = functools.cmp_to_key(compare_versions)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def severity_from_cvss(score: float | None) -> str | None:
    """Map a CVSS v3.x base score to CRITICAL / HIGH / MEDIUM / LOW (``None`` for 0 or unknown)."""
    if score is None or score <= 0:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def map_osv_ecosystem(name: str) -> Ecosystem | None:
    """Map an OSV ecosystem string (``PyPI``, ``Go``, ``Maven:...``) to the internal enum."""
    return _OSV_ECOSYSTEMS.get(name.split(":", 1)[0].strip().lower())


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _first_sentence(text: str, limit: int = 200) -> str:
    sentence = re.split(r"(?<=[.!?])\s", text.strip(), maxsplit=1)[0]
    return sentence[:limit]


def _pick_nvd_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    """Prefer CVSS v3.1 over v3.0, and the NVD ``Primary`` source over secondary ones."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entries = sorted(entries, key=lambda e: e.get("type") != "Primary")
        data = entries[0].get("cvssData", {})
        if data.get("baseScore") is not None:
            return float(data["baseScore"]), data.get("vectorString")
    return None, None


def normalise_nvd(vuln: dict[str, Any]) -> CVERecord:
    """Normalise one element of NVD's ``vulnerabilities`` array.

    NVD supplies CVSS, KEV status and description. Package-level affected ranges are left
    empty on purpose: NVD CPE data is unreliable for package ecosystems, OSV is used for that.
    """
    cve = vuln["cve"]
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    score, vector = _pick_nvd_cvss(cve.get("metrics", {}))
    return CVERecord(
        cve_id=cve["id"].upper(),
        title=cve.get("cisaVulnerabilityName") or (_first_sentence(description) if description else None),
        description=description,
        cvss_v3_score=score,
        cvss_v3_vector=vector,
        severity=severity_from_cvss(score),
        cisa_kev=bool(cve.get("cisaExploitAdd")),
        published_at=_parse_dt(cve.get("published")),
        source="NVD",
        raw_data={"nvd": vuln},
    )


def _range_to_strings(events: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Convert OSV range events to human-readable constraints plus the fixed versions found."""
    constraints: list[str] = []
    fixed_versions: list[str] = []
    introduced: str | None = None
    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
        elif "fixed" in event or "last_affected" in event:
            is_fix = "fixed" in event
            bound = event["fixed"] if is_fix else event["last_affected"]
            op = "<" if is_fix else "<="
            lower = f">= {introduced}, " if introduced not in (None, "0") else ""
            constraints.append(f"{lower}{op} {bound}")
            if is_fix:
                fixed_versions.append(bound)
            introduced = None
    if introduced is not None:  # introduced with no fix yet
        constraints.append("all versions" if introduced == "0" else f">= {introduced}")
    return constraints, fixed_versions


def normalise_osv(vuln: dict[str, Any], cve_id: str | None = None) -> CVERecord:
    """Normalise an OSV vulnerability record (``GET /v1/vulns/{id}`` or an element of ``/v1/query``).

    OSV is authoritative for affected ranges and fixed versions. Records in unsupported
    ecosystems produce an empty ``affected_packages`` list.
    """
    if cve_id is None:
        cve_id = next((a for a in [vuln.get("id", ""), *vuln.get("aliases", [])] if _CVE_RE.match(a)), None)
    if cve_id is None:
        raise ValueError(f"OSV record {vuln.get('id')} has no CVE alias")

    merged: dict[tuple[Ecosystem, str], AffectedPackage] = {}
    for affected in vuln.get("affected", []):
        pkg = affected.get("package") or {}
        eco = map_osv_ecosystem(pkg.get("ecosystem", ""))
        name = pkg.get("name")
        if eco is None or not name:
            continue
        constraints: list[str] = []
        fixes: list[str] = []
        for rng in affected.get("ranges", []):
            if rng.get("type") == "GIT":
                continue
            c, f = _range_to_strings(rng.get("events", []))
            constraints += c
            fixes += f
        entry = merged.setdefault((eco, name), AffectedPackage(ecosystem=eco, package_name=name))
        entry.affected_versions = list(dict.fromkeys([*entry.affected_versions, *constraints]))
        all_fixes = [*([entry.fixed_version] if entry.fixed_version else []), *fixes]
        if all_fixes:
            entry.fixed_version = min(all_fixes, key=_version_sort_key)

    return CVERecord(
        cve_id=cve_id.upper(),
        title=vuln.get("summary"),
        description=vuln.get("details") or vuln.get("summary"),
        affected_packages=list(merged.values()),
        published_at=_parse_dt(vuln.get("published")),
        source="OSV",
        raw_data={"osv": [vuln]},
    )


def merge_records(records: list[CVERecord]) -> CVERecord:
    """Merge records for the same CVE ID from different sources.

    NVD wins for CVSS / KEV / title / description / publish date; OSV wins for affected
    packages. Raw payloads from every source are kept under ``raw_data``.
    """
    if not records:
        raise ValueError("merge_records requires at least one record")
    ids = {r.cve_id for r in records}
    if len(ids) != 1:
        raise ValueError(f"cannot merge records for different CVEs: {sorted(ids)}")

    nvd = [r for r in records if r.source == "NVD"]
    osv = [r for r in records if r.source == "OSV"]
    base = (nvd or osv)[0]
    merged = base.model_copy(deep=True)

    if nvd and osv:
        merged.source = "NVD+OSV"
    packages: dict[tuple[Ecosystem, str], AffectedPackage] = {}
    for rec in osv or records:
        for pkg in rec.affected_packages:
            key = (pkg.ecosystem, pkg.package_name)
            if key in packages:
                prev = packages[key]
                prev.affected_versions = list(dict.fromkeys([*prev.affected_versions, *pkg.affected_versions]))
                fixes = [v for v in (prev.fixed_version, pkg.fixed_version) if v]
                prev.fixed_version = min(fixes, key=_version_sort_key) if fixes else None
            else:
                packages[key] = pkg.model_copy(deep=True)
    merged.affected_packages = list(packages.values())

    raw: dict[str, Any] = {}
    for rec in records:
        for key, value in rec.raw_data.items():
            if key == "osv":
                raw.setdefault("osv", []).extend(value)
            else:
                raw[key] = value
    merged.raw_data = raw

    # Fill gaps from any record (e.g. OSV-only descriptions when NVD has none).
    for rec in records:
        merged.title = merged.title or rec.title
        merged.description = merged.description or rec.description
        merged.published_at = merged.published_at or rec.published_at
    return merged
