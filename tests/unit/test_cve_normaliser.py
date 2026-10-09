import json
from pathlib import Path

import pytest

from src.schemas.cve import Ecosystem
from src.services.cve_aggregator.normaliser import (
    map_osv_ecosystem,
    merge_records,
    normalise_nvd,
    normalise_osv,
    severity_from_cvss,
)

FIX = Path(__file__).resolve().parents[1] / "fixtures"


def load(name: str):
    return json.loads((FIX / name).read_text())


@pytest.mark.parametrize(
    "score,expected",
    [(10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"), (6.9, "MEDIUM"),
     (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, None), (None, None)],
)  # fmt: skip
def test_severity_bands(score, expected):
    assert severity_from_cvss(score) == expected


@pytest.mark.parametrize(
    "osv,expected",
    [("PyPI", Ecosystem.PIP), ("npm", Ecosystem.NPM), ("Go", Ecosystem.GO), ("RubyGems", Ecosystem.GEM),
     ("NuGet", Ecosystem.NUGET), ("Maven", Ecosystem.MAVEN), ("Maven:https://x.y/repo", Ecosystem.MAVEN),
     ("crates.io", None), ("Debian:11", None)],
)  # fmt: skip
def test_ecosystem_mapping(osv, expected):
    assert map_osv_ecosystem(osv) == expected


def test_normalise_nvd():
    rec = normalise_nvd(load("nvd_cve_2024_21626.json")["vulnerabilities"][0])
    assert rec.cve_id == "CVE-2024-21626"
    assert rec.cvss_v3_score == 8.6 and rec.severity == "HIGH"
    assert rec.cvss_v3_vector.endswith("UI:R/S:C/C:H/I:H/A:H")  # Primary source preferred
    assert rec.cisa_kev is True
    assert rec.title == "runc Process Capabilities Vulnerability"
    assert "fixed in runc 1.1.12" in rec.description  # English description, not Spanish
    assert rec.published_at.year == 2024 and rec.published_at.tzinfo is not None
    assert rec.affected_packages == [] and rec.source == "NVD"


def test_normalise_nvd_without_metrics_or_kev():
    rec = normalise_nvd({"cve": {"id": "cve-2030-1", "descriptions": [{"lang": "en", "value": "First. Second."}]}})
    assert rec.cve_id == "CVE-2030-1"
    assert rec.cvss_v3_score is None and rec.severity is None and rec.cisa_kev is False
    assert rec.title == "First."


def test_nvd_falls_back_to_v30():
    rec = normalise_nvd({"cve": {"id": "CVE-2030-2", "metrics": {"cvssMetricV30": [
        {"type": "Primary", "cvssData": {"baseScore": 5.5, "vectorString": "CVSS:3.0/AV:L"}}]}}})
    assert (rec.cvss_v3_score, rec.severity) == (5.5, "MEDIUM")


def test_normalise_osv_go_and_drops_unsupported():
    rec = normalise_osv(load("osv_ghsa_xr7r_f8xq_vfvv.json"))
    assert rec.cve_id == "CVE-2024-21626"
    assert len(rec.affected_packages) == 1
    pkg = rec.affected_packages[0]
    assert pkg.ecosystem == Ecosystem.GO and pkg.package_name == "github.com/opencontainers/runc"
    assert pkg.fixed_version == "1.1.12"
    assert pkg.affected_versions == [">= 0.0.0-rc93, < 1.1.12"]


def test_normalise_osv_multi_branch_ranges():
    rec = normalise_osv(load("osv_pypi_multi_branch.json"))
    (pkg,) = rec.affected_packages  # same package in two affected[] entries is merged
    assert pkg.ecosystem == Ecosystem.PIP
    assert pkg.affected_versions == ["< 1.4.9", ">= 2.0.0, < 2.0.3", ">= 3.0.0, <= 3.1.0"]
    assert pkg.fixed_version == "1.4.9"  # lowest fix; GIT ranges ignored


def test_normalise_osv_requires_cve_alias():
    with pytest.raises(ValueError):
        normalise_osv({"id": "GHSA-aaaa-bbbb-cccc", "aliases": []})


def test_merge_prefers_nvd_scores_and_osv_packages():
    nvd = normalise_nvd(load("nvd_cve_2024_21626.json")["vulnerabilities"][0])
    osv = normalise_osv(load("osv_ghsa_xr7r_f8xq_vfvv.json"))
    merged = merge_records([osv, nvd])  # order must not matter
    assert merged.source == "NVD+OSV"
    assert merged.cvss_v3_score == 8.6 and merged.cisa_kev is True
    assert merged.title == "runc Process Capabilities Vulnerability"
    assert [p.fixed_version for p in merged.affected_packages] == ["1.1.12"]
    assert set(merged.raw_data) == {"nvd", "osv"}
    assert isinstance(merged.raw_data["osv"], list)


def test_merge_osv_only_fills_description():
    osv = normalise_osv(load("osv_ghsa_xr7r_f8xq_vfvv.json"))
    merged = merge_records([osv])
    assert merged.source == "OSV" and merged.description and merged.cvss_v3_score is None


def test_merge_rejects_mixed_cves():
    a = normalise_nvd({"cve": {"id": "CVE-2030-1"}})
    b = normalise_nvd({"cve": {"id": "CVE-2030-2"}})
    with pytest.raises(ValueError):
        merge_records([a, b])
    with pytest.raises(ValueError):
        merge_records([])
