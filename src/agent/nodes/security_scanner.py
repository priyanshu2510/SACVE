"""Node 9: scan the patched environment with grype and confirm the CVE is gone."""

from __future__ import annotations

import json
from typing import Any

from src.agent.deps import get_sandbox_manager
from src.agent.nodes import _pip
from src.agent.nodes._common import NodeError, agent_node, make_event, record_failure
from src.agent.state import AgentState
from src.core.config import settings

SCANNER_SCORE = 5
SCAN_TARGETS = (("workspace", "dir:/workspace"), ("venv", f"dir:{_pip.VENV}"))


def matches_cve(grype_json: dict[str, Any], cve_id: str) -> list[dict[str, str]]:
    """Return ``{package, version, id}`` for every match whose id or related ids include ``cve_id``."""
    wanted = cve_id.upper()
    hits: list[dict[str, str]] = []
    for match in grype_json.get("matches", []):
        vuln = match.get("vulnerability", {})
        ids = {str(vuln.get("id", "")).upper()}
        ids |= {str(r.get("id", "")).upper() for r in match.get("relatedVulnerabilities", [])}
        if wanted in ids:
            artifact = match.get("artifact", {})
            hits.append({"package": artifact.get("name", "?"), "version": artifact.get("version", "?"), "id": vuln.get("id", "")})
    return hits


@agent_node("run_security_scan")
async def run_security_scan(state: AgentState) -> dict[str, Any]:
    """Run grype against the workspace and the installed environment (offline, baked-in DB).

    Scanner infrastructure problems are errors; the CVE still being present is a repairable failure.
    """
    if not state.sandbox_container_id:
        raise NodeError("run_security_scan requires a sandbox")
    sandbox = await get_sandbox_manager().attach(state.sandbox_container_id)

    hits: list[dict[str, str]] = []
    totals: dict[str, int] = {}
    for label, target in SCAN_TARGETS:
        out_file = f"/tmp/grype-{label}.json"
        run = await sandbox.exec(["grype", target, "-q", "-o", f"json={out_file}"], timeout=settings.SANDBOX_TIMEOUT_SECONDS)
        if not run.ok:
            raise NodeError(f"grype failed on {target} (exit {run.exit_code}): {run.output[-300:]}")
        cat = await sandbox.exec(["cat", out_file], timeout=60)  # /tmp is outside the workspace
        if not cat.ok:
            raise NodeError(f"could not read grype report for {target}")
        raw = cat.output
        try:
            report = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise NodeError(f"grype produced invalid JSON for {target}: {exc}") from exc
        totals[label] = len(report.get("matches", []))
        hits += matches_cve(report, state.cve_id)

    summary = json.dumps({"cve_matches": hits, "total_matches": totals})
    if hits:
        found = ", ".join(f"{h['package']} {h['version']}" for h in hits)
        return record_failure(
            state,
            f"{state.cve_id} is still reported by the scanner after the fix (affected: {found})",
            events=[("SCAN_FAILED", {"cve_matches": hits, "total_matches": totals})],
        ) | {"scanner_cve_resolved": False, "scanner_output": summary}

    breakdown = dict(state.confidence_breakdown or {})
    breakdown["scanner"] = SCANNER_SCORE
    return {
        "scanner_cve_resolved": True,
        "scanner_output": summary,
        "confidence_score": (state.confidence_score or 0) + SCANNER_SCORE,
        "confidence_breakdown": breakdown,
        "audit_events": [*state.audit_events, make_event("SCAN_CONFIRMED", {"total_matches": totals})],
    }
