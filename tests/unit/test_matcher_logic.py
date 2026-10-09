from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from src.core.config import Settings
from src.models.job import JobStatus
from src.services.matcher.repo_filter import RepoFilter, load_static_filter
from src.services.matcher.vulnerability_matcher import canonical_name, decide, evaluate, match_components, parse_range
from src.services.sbom.generator import SBOMComponent
from src.schemas.cve import Ecosystem

MULTI = ["< 1.4.9", ">= 2.0.0, < 2.0.3", ">= 3.0.0, <= 3.1.0"]


@pytest.mark.parametrize(
    "expr,expected",
    [("< 1.4.9", [("<", "1.4.9")]), (">= 2.0.0, < 2.0.3", [(">=", "2.0.0"), ("<", "2.0.3")]), ("all versions", []),
     (">=1.0", [(">=", "1.0")]), ("~> 1.2", None), ("", None), ("< ", None)],
)  # fmt: skip
def test_parse_range(expr, expected):
    assert parse_range(expr) == expected


@pytest.mark.parametrize(
    "installed,ranges,fixed,affected,safe",
    [
        ("1.1.5", ["< 1.1.12"], "1.1.12", True, "1.1.12"),
        ("1.1.12", ["< 1.1.12"], "1.1.12", False, None),
        ("1.1.13", ["< 1.1.12"], "1.1.12", False, None),
        ("v1.1.5", [">= 1.0.0-rc93, < 1.1.12"], "1.1.12", True, "1.1.12"),  # Go 'v' prefix, prerelease lower bound
        ("1.4.2", MULTI, "1.4.9", True, "1.4.9"),  # per-branch fix
        ("2.0.1", MULTI, "1.4.9", True, "2.0.3"),  # not the lowest fix (1.4.9 would be a downgrade)
        ("2.0.3", MULTI, "1.4.9", False, None),
        ("3.0.5", MULTI, "1.4.9", True, None),  # last_affected only: no fix newer than 3.1.0 is known
        ("3.2.0", MULTI, "1.4.9", False, None),
        ("1.5.0", ["< 2.0", "< 3.0"], None, True, "3.0"),  # overlapping ranges: must clear both
        ("1.2.4", [">= 1.2.3"], None, True, None),  # open-ended
        ("5.0", ["all versions"], None, True, None),
        ("2.0", ["garbage", "< 3.0"], "3.0", True, "3.0"),  # unparsable ranges are ignored
        ("2.0", ["garbage"], "3.0", False, None),
        ("1.0.0", ["<= 1.0.0"], "1.0.1", True, "1.0.1"),  # fixed_version supplies the fix for a last_affected range
        ("2.31.0", ["< 2.32.0"], "2.32.0", True, "2.32.0"),
    ],
)  # fmt: skip
def test_evaluate(installed, ranges, fixed, affected, safe):
    ev = evaluate(installed, ranges, fixed)
    assert (ev.affected, ev.safe_version) == (affected, safe)


@pytest.mark.parametrize(
    "eco,a,b",
    [("pip", "PyYAML", "pyyaml"), ("pip", "Foo_Bar.baz", "foo-bar-baz"), ("npm", "Lodash", "lodash"),
     ("maven", "Org.X:Y", "org.x:y"), ("go", "github.com/A/B", "github.com/a/b")],
)  # fmt: skip
def test_canonical_name(eco, a, b):
    assert canonical_name(eco, a) == canonical_name(eco, b)


def pkg(eco="pip", name="requests", versions=("< 2.32.0",), fixed="2.32.0"):
    return SimpleNamespace(ecosystem=eco, package_name=name, affected_versions=list(versions), fixed_version=fixed)


def cve(*pkgs, cvss=5.6, severity="MEDIUM"):
    return SimpleNamespace(cve_id="CVE-2024-35195", cvss_v3_score=cvss, severity=severity, affected_packages=list(pkgs))


def comp(name="requests", version="2.31.0", eco=Ecosystem.PIP, path="requirements.txt"):
    return SBOMComponent(eco, name, version, path, f"pkg:{eco.value}/{name}@{version}")


def test_match_components_finds_affected_and_reports_no_fix(uuid_=None):
    import uuid

    rid = uuid.uuid4()
    impacts, no_fix = match_components(cve(pkg()), rid, "org/api", [comp(), comp("flask", "3.0.0"), comp("Requests", "2.32.0")])
    assert [(i.package, i.installed_version, i.safe_version, i.manifest_path) for i in impacts] == [("requests", "2.31.0", "2.32.0", "requirements.txt")] and no_fix == 0
    assert impacts[0].cvss == 5.6 and impacts[0].repo_name == "org/api"

    impacts, no_fix = match_components(cve(pkg(versions=("all versions",), fixed=None)), rid, "org/api", [comp()])
    assert impacts == [] and no_fix == 1


def test_match_components_ecosystem_and_name_must_both_match():
    import uuid

    c = cve(pkg(eco="npm", name="requests"))
    assert match_components(c, uuid.uuid4(), "o/r", [comp()])[0] == []  # same name, different ecosystem
    assert match_components(cve(pkg(name="PyYAML", versions=("< 6",), fixed="6")), uuid.uuid4(), "o/r", [comp("pyyaml", "5.3.1")])[0]


# ------------------------------------------------------------------ job policy
NOW = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
CFG = Settings(_env_file=None)


def job(status, age_hours=0):
    t = NOW - timedelta(hours=age_hours)
    return SimpleNamespace(status=status, updated_at=t, created_at=t)


@pytest.mark.parametrize(
    "j,action,reason",
    [
        (None, "create", ""),
        (job(JobStatus.MERGED, 999), "skip", "merged"),
        (job(JobStatus.BLOCKED, 999), "skip", "blocked"),
        (job(JobStatus.NOT_REACHABLE, 999), "skip", "not_reachable"),
        (job(JobStatus.CANCELLED, 999), "skip", "cancelled"),
        (job(JobStatus.PR_RAISED, 999), "skip", "in_flight"),
        (job(JobStatus.RUNNING, 999), "skip", "in_flight"),
        (job(JobStatus.PAUSED, 999), "skip", "in_flight"),
        (job(JobStatus.FAILED, 1), "skip", "failed_recently"),
        (job(JobStatus.FAILED, 25), "requeue", "failed_retry"),
        (job(JobStatus.QUEUED, 1), "skip", "in_flight"),
        (job(JobStatus.QUEUED, 7), "requeue", "stale_queue"),
    ],
)  # fmt: skip
def test_decide(j, action, reason):
    d = decide(j, NOW, CFG)
    assert (d.action, d.reason) == (action, reason)


# ------------------------------------------------------------------ repo filter
def test_repo_filter_rules():
    f = RepoFilter.from_lists(["org/api", "Web"], ["org/legacy", "old"])
    assert f.check("org/api") == (True, "ok") and f.check("ORG/web") == (True, "ok")  # short or full name, any case
    assert f.check("org/other") == (False, "not allowlisted")
    assert f.check("org/legacy") == (False, "blocklisted") and f.check("x/old") == (False, "blocklisted")
    assert f.check("org/api", archived=True) == (False, "archived")
    assert f.check("org/api", topics=["Python", "CVE-Exempt"]) == (False, "cve-exempt")


def test_blocklist_beats_allowlist_and_empty_allowlist_means_all():
    assert not RepoFilter.from_lists(["a"], ["a"]).allows("o/a")
    assert RepoFilter.from_lists([], []).allows("any/thing")


def test_static_filter_merges_yaml_and_env(tmp_path):
    path = tmp_path / "repos.yaml"
    path.write_text("allowlist: [api]\nblocklist: [from-yaml]\n")
    f = load_static_filter(Settings(_env_file=None, REPO_BLOCKLIST="from-env", REPO_ALLOWLIST="web"), path)
    assert f.allows("o/api") and f.allows("o/web") and not f.allows("o/from-yaml") and not f.allows("o/other")
    assert load_static_filter(Settings(_env_file=None), tmp_path / "missing.yaml").allows("o/x")
