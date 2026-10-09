from src.agent.deps import override_deps
from src.agent.nodes.security_scanner import matches_cve, run_security_scan
from tests.fakes import FakeSandboxManager


def test_matches_cve_by_id_or_related():
    report = {"matches": [
        {"vulnerability": {"id": "CVE-2024-35195"}, "artifact": {"name": "requests", "version": "2.31.0"}},
        {"vulnerability": {"id": "GHSA-x"}, "relatedVulnerabilities": [{"id": "cve-2024-35195"}], "artifact": {"name": "requests", "version": "2.31.0"}},
        {"vulnerability": {"id": "CVE-2023-1"}, "artifact": {"name": "flask", "version": "1"}},
    ]}  # fmt: skip
    assert [h["id"] for h in matches_cve(report, "CVE-2024-35195")] == ["CVE-2024-35195", "GHSA-x"]
    assert matches_cve({}, "CVE-2024-35195") == []


async def scan(make_state, installed_requirements, **kw):
    mgr = FakeSandboxManager({"requirements.txt": installed_requirements}, **kw)
    sb = await mgr.create(job_id="j", repo_name="o/r", ecosystem="pip")
    sb.installed = {"requests": installed_requirements.split("==")[1].strip()}
    state = make_state(sandbox_container_id=sb.container_id, fix_attempt=1, confidence_score=85, confidence_breakdown={"scanner": 0})
    with override_deps(sandbox_manager=mgr):
        return sb, await run_security_scan(state)


async def test_resolved_adds_scanner_points(make_state):
    sb, out = await scan(make_state, "requests==2.32.0\n")
    assert out["scanner_cve_resolved"] is True and out["confidence_score"] == 90
    assert out["confidence_breakdown"]["scanner"] == 5
    assert out["audit_events"][-1]["event_type"] == "SCAN_CONFIRMED"
    targets = [c[1] for c in sb.calls if c[0] == "grype"]
    assert targets == ["dir:/workspace", "dir:/opt/venv"]


async def test_still_vulnerable_is_repairable(make_state):
    _, out = await scan(make_state, "requests==2.31.0\n")
    assert out["scanner_cve_resolved"] is False and "still reported" in out["failure_reason"]
    assert "requests 2.31.0" in out["failure_reason"] and "confidence_score" not in out
    assert [e["event_type"] for e in out["audit_events"][-2:]] == ["SCAN_FAILED", "FIX_ATTEMPT_FAILED"]


async def test_scanner_infrastructure_failure_is_an_error(make_state):
    _, out = await scan(make_state, "requests==2.32.0\n", scan_error=True)
    assert "grype failed" in out["error"] and "failure_reason" not in out


async def test_requires_sandbox(make_state):
    assert "requires a sandbox" in (await run_security_scan(make_state()))["error"]
