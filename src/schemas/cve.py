"""Pydantic schemas for normalised CVE data (cross-service boundary)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Ecosystem(str, Enum):
    """Internal ecosystem names (the six supported package ecosystems)."""

    NPM = "npm"
    PIP = "pip"
    MAVEN = "maven"
    GO = "go"
    NUGET = "nuget"
    GEM = "gem"


class AffectedPackage(BaseModel):
    """A package affected by a CVE."""

    ecosystem: Ecosystem
    package_name: str
    affected_versions: list[str] = Field(default_factory=list)  # e.g. ["< 1.1.12", ">= 2.0.0, < 2.0.3"]
    fixed_version: str | None = None  # lowest fixed version; per-branch fixes are in affected_versions


class CVERecord(BaseModel):
    """Normalised internal CVE schema."""

    cve_id: str
    title: str | None = None
    description: str | None = None
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    severity: str | None = None  # CRITICAL | HIGH | MEDIUM | LOW
    affected_packages: list[AffectedPackage] = Field(default_factory=list)
    cisa_kev: bool = False
    published_at: datetime | None = None
    source: str = "NVD"  # NVD | OSV | NVD+OSV
    raw_data: dict[str, Any] = Field(default_factory=dict)
