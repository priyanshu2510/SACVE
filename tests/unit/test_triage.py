from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from src.services.triage.prioritiser import JIRA_PRIORITY, triage


@dataclass
class C:
    cve_id: str
    cvss_v3_score: float | None
    severity: str | None = None
    cisa_kev: bool = False
    published_at: datetime | None = None


def ids(result):
    return [t.cve_id for t in result.kept]


def test_priority_bands_and_threshold():
    r = triage([C("a", 9.8, "CRITICAL"), C("b", 7.5, "HIGH"), C("c", 5.0, "MEDIUM"), C("d", 4.0, "MEDIUM"), C("e", 3.9, "LOW")], 4.0)
    assert [(t.cve_id, t.priority) for t in r.kept] == [("a", "P1"), ("b", "P2"), ("c", "P3"), ("d", "P3")]
    assert [(d.cve_id, d.reason) for d in r.dropped] == [("e", "below_threshold")]


def test_unscored_dropped_but_kev_always_kept_and_first():
    r = triage([C("hi", 9.9, "CRITICAL"), C("none", None), C("kev-low", 2.0, "LOW", True), C("kev-unscored", None, None, True)], 4.0)
    assert ids(r) == ["kev-low", "kev-unscored", "hi"]  # KEV outranks everything, even a 9.9
    assert [t.priority for t in r.kept] == ["P4", "P2", "P1"]  # priority still reflects severity; unscored KEV defaults to HIGH
    assert [(d.cve_id, d.reason) for d in r.dropped] == [("none", "unscored")]


def test_ranking_by_score_then_age_then_id():
    old, new = datetime(2020, 1, 1, tzinfo=timezone.utc), datetime(2025, 1, 1, tzinfo=timezone.utc)
    r = triage([C("z", 8.0, "HIGH", published_at=new), C("y", 8.0, "HIGH", published_at=old), C("x", 9.0, "CRITICAL", published_at=new),
                C("w", 8.0, "HIGH", published_at=old)], 4.0)  # fmt: skip
    assert ids(r) == ["x", "w", "y", "z"]  # higher score first; ties: older first, then id


def test_default_threshold_comes_from_settings(monkeypatch):
    from src.services.triage import prioritiser

    monkeypatch.setattr(prioritiser.settings, "MIN_CVSS_THRESHOLD", 7.0)
    assert ids(triage([C("a", 6.9, "MEDIUM"), C("b", 7.0, "HIGH")])) == ["b"]


def test_jira_priority_labels():
    assert JIRA_PRIORITY["P1"] == "P1 - Critical" and JIRA_PRIORITY["P4"] == "P4 - Low"


def test_empty():
    r = triage([])
    assert r.kept == [] and r.dropped == []
