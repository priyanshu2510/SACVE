"""Node 3: partial confidence score (before test and scanner results).

Maximum partial score is 70: severity 20 + fix simplicity 25 + LLM certainty 15 + advisory 10.
The test-pass (25) and scanner (5) components are added by later nodes.
"""

from __future__ import annotations

import posixpath
from typing import Any

from src.agent.nodes._common import agent_node, with_event
from src.agent.state import AgentState, FileChange

SEVERITY_MAX = 20
SIMPLICITY_VERSION_BUMP = 25
SIMPLICITY_CONFIG_CHANGE = 15
SIMPLICITY_CODE_REWRITE = 5
LLM_MAX = 15
ADVISORY_MAX = 10

_MANIFEST_NAMES = {
    "pipfile", "pipfile.lock", "pyproject.toml", "poetry.lock", "uv.lock", "package.json", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "go.mod", "go.sum", "pom.xml", "gradle.lockfile",
    "gemfile", "gemfile.lock", "packages.config", "directory.packages.props", "packages.lock.json",
}  # fmt: skip
_MANIFEST_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".gemspec")
_CONFIG_SUFFIXES = (".yaml", ".yml", ".toml", ".cfg", ".ini", ".json", ".properties", ".conf", ".gradle", ".kts")


def _is_manifest(path: str, declared_manifest: str) -> bool:
    name = posixpath.basename(path).lower()
    return (
        path == declared_manifest
        or name in _MANIFEST_NAMES
        or name.endswith(_MANIFEST_SUFFIXES)
        or (name.endswith(".txt") and name.startswith(("requirements", "constraints")))
    )


def classify_fix(changes: list[FileChange], declared_manifest: str) -> tuple[str, int]:
    """Return ``(class, points)``: ``version_bump`` 25, ``config_change`` 15, ``code_rewrite`` 5."""
    if all(_is_manifest(c.file_path, declared_manifest) for c in changes):
        return "version_bump", SIMPLICITY_VERSION_BUMP
    if all(
        _is_manifest(c.file_path, declared_manifest) or c.file_path.lower().endswith(_CONFIG_SUFFIXES)
        for c in changes
    ):
        return "config_change", SIMPLICITY_CONFIG_CHANGE
    return "code_rewrite", SIMPLICITY_CODE_REWRITE


@agent_node("score_confidence")
async def score_confidence(state: AgentState) -> dict[str, Any]:
    """Compute the partial confidence score. No-ops when an upstream error is set."""
    if state.error or not state.file_changes:
        return {}

    severity = max(0, min(SEVERITY_MAX, round(state.cvss_score / 10 * SEVERITY_MAX)))
    simplicity_class, simplicity = classify_fix(state.file_changes, state.manifest_file_path)
    llm = max(0, min(LLM_MAX, round((state.llm_self_confidence or 0) / 100 * LLM_MAX)))
    advisory = ADVISORY_MAX if (state.context_payload or {}).get("cve", {}).get("advisory_fix_verified") else 0

    total = severity + simplicity + llm + advisory
    breakdown = {
        "severity": severity,
        "simplicity": simplicity,
        "simplicity_class": simplicity_class,
        "llm_certainty": llm,
        "advisory": advisory,
        "tests": 0,  # added after run_post_tests (max 25)
        "scanner": 0,  # added after run_security_scan (max 5)
        "partial": True,
    }
    return {
        "confidence_score": total,
        "confidence_breakdown": breakdown,
        "audit_events": with_event(state, "CONFIDENCE_SCORED", {"score": total, "breakdown": breakdown}),
    }
