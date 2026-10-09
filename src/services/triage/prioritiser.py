"""CVE triage: priority from CVSS v3 severity, CISA KEV flag, and the minimum-score cut."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from src.core.config import settings

PRIORITY_BY_SEVERITY = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}
JIRA_PRIORITY = {"P1": "P1 - Critical", "P2": "P2 - High", "P3": "P3 - Medium", "P4": "P4 - Low"}


class TriageInput(Protocol):
    """What triage needs from a CVE (satisfied by both ``CVERecord`` and the ORM ``CVE``)."""

    cve_id: str
    cvss_v3_score: float | None
    severity: str | None
    cisa_kev: bool
    published_at: datetime | None


@dataclass(frozen=True)
class TriagedCVE:
    """A CVE that passed triage."""

    cve_id: str
    cvss: float | None
    severity: str
    priority: str  # P1..P4
    kev: bool


@dataclass(frozen=True)
class Dropped:
    """A CVE that did not pass triage, with the reason."""

    cve_id: str
    reason: str  # unscored | below_threshold


@dataclass(frozen=True)
class TriageResult:
    """Priority-ranked CVEs (most urgent first) plus what was dropped and why."""

    kept: list[TriagedCVE]
    dropped: list[Dropped]


def triage(cves: Iterable[TriageInput], min_cvss: float | None = None) -> TriageResult:
    """Rank CVEs and drop the ones below ``MIN_CVSS_THRESHOLD``.

    Known-exploited (CISA KEV) CVEs are never dropped, even when unscored or below the threshold,
    and rank first. Unscored non-KEV CVEs are dropped until NVD publishes a score (they come back
    on a later sync, since NVD reports the rescoring as a modification).
    """
    threshold = settings.MIN_CVSS_THRESHOLD if min_cvss is None else min_cvss
    ranked: list[tuple[tuple, TriagedCVE]] = []
    dropped: list[Dropped] = []
    for cve in cves:
        score = cve.cvss_v3_score
        if not cve.cisa_kev:
            if score is None:
                dropped.append(Dropped(cve.cve_id, "unscored"))
                continue
            if score < threshold:
                dropped.append(Dropped(cve.cve_id, "below_threshold"))
                continue
        severity = (cve.severity or ("HIGH" if cve.cisa_kev else "MEDIUM")).upper()
        item = TriagedCVE(cve.cve_id, score, severity, PRIORITY_BY_SEVERITY.get(severity, "P3"), cve.cisa_kev)
        published = cve.published_at.timestamp() if cve.published_at else float("inf")
        ranked.append(((not cve.cisa_kev, -(score or 0.0), published, cve.cve_id), item))
    ranked.sort(key=lambda pair: pair[0])
    return TriageResult([item for _, item in ranked], dropped)
