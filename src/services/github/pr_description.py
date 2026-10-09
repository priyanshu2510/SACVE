"""Pull-request title / body rendering (spec template) with sanitisation of untrusted text."""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.agent.state import AgentState

ZWSP = "​"
MARKER_RE = re.compile(r"<!-- cve-remediation-bot job_id=(?P<job>[\w-]+) cve=(?P<cve>CVE-[\d-]+) -->")

DEFAULT_HIGH, DEFAULT_MEDIUM = 85, 70  # recalibrated against PR outcomes by the calibration job
TIER_TEXT = {
    "HIGH": "all validation checks passed with a simple, low-risk change",
    "MEDIUM": "validation passed, but the change or its risk warrants a careful look",
    "LOW": "validation passed with low overall confidence; review thoroughly before merging",
}


@dataclass(frozen=True)
class Tier:
    """Confidence tier shown in the PR."""

    label: str
    description: str


def confidence_tier(score: int, thresholds: tuple[int, int] = (DEFAULT_HIGH, DEFAULT_MEDIUM)) -> Tier:
    """Map a 0-100 confidence score to its tier; ``thresholds`` is ``(high, medium)``."""
    high, medium = thresholds
    label = "HIGH" if score >= high else "MEDIUM" if score >= medium else "LOW"
    return Tier(label, TIER_TEXT[label])


def sanitize_markdown(text: str) -> str:
    """Neutralise LLM/CVE-derived text before it enters a PR body.

    Prevents HTML injection, ``@mention`` and ``#123`` notification spam, and image beacons.
    """
    text = text.replace("&", "&amp;").replace("<", "&lt;")
    text = re.sub(r"(?<![\w`])@(?=[A-Za-z0-9])", "@" + ZWSP, text)
    text = re.sub(r"(?<![\w&])#(?=\d)", "#" + ZWSP, text)
    return text.replace("![", "!" + ZWSP + "[")


def one_line(text: str, limit: int = 200) -> str:
    """Collapse to a single sanitised line (titles, table cells)."""
    return sanitize_markdown(" ".join(text.split()))[:limit].replace("|", "\\|")


def pr_title(state: AgentState) -> str:
    """``fix(high): CVE-… bump pkg 1.0 -> 1.1``."""
    return one_line(
        f"fix({state.severity.lower()}): {state.cve_id} bump {state.affected_package} "
        f"{state.installed_version} → {state.target_version}",
        120,
    )


def pr_marker(state: AgentState) -> str:
    """Hidden marker used by the dedup guard to recognise our PRs and the job that made them."""
    return f"<!-- cve-remediation-bot job_id={state.job_id} cve={state.cve_id} -->"


def render_pr_body(state: AgentState, control_api_url: str, thresholds: tuple[int, int] = (DEFAULT_HIGH, DEFAULT_MEDIUM)) -> str:
    """Render the standard PR description (``thresholds`` = calibrated ``(high, medium)`` tier cut-offs)."""
    score = state.confidence_score or 0
    tier = confidence_tier(score, thresholds)
    bd = state.confidence_breakdown or {}
    pre, post = state.pre_fix_tests, state.post_fix_tests
    notes = state.breaking_change_notes
    cve = state.cve_id
    lines = [
        f"## 🔒 Security Fix: {cve} ({state.severity}, CVSS {state.cvss_score})",
        "",
        "> **Generated automatically by the CVE Auto-Remediation Platform.**",
        "> Review carefully before merging.",
        "",
        "### Vulnerability Details",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| CVE ID | [{cve}](https://nvd.nist.gov/vuln/detail/{cve}) |",
        f"| Package | `{one_line(state.affected_package)}` |",
        f"| Severity | {state.severity} |",
        f"| CVSS Score | {state.cvss_score} |",
        f"| Fix | `{one_line(state.installed_version)}` → `{one_line(state.target_version)}` |",
        "",
        "### What Changed",
        "",
        sanitize_markdown(state.llm_explanation or "_No explanation provided._"),
        "",
    ]
    if state.reachable is False:
        reason = (state.reachability_evidence or {}).get("reason", "no usage found")
        lines += [
            "> ℹ️ **Reachability:** static analysis found no use of this package in the repository "
            f"({one_line(str(reason))}). The fix was still raised (advisory mode).",
            "",
        ]
    lines += [
        f"### Confidence Score: {score} / 100",
        "",
        f"**{tier.label}** — {tier.description}",
        "",
        "| Factor | Score |",
        "|---|---|",
        f"| CVE Severity | {bd.get('severity', 0)} / 20 |",
        f"| Fix Simplicity | {bd.get('simplicity', 0)} / 25 |",
        f"| LLM Certainty | {bd.get('llm_certainty', 0)} / 15 |",
        f"| Test Pass Rate | {bd.get('tests', 0)} / 25 |",
        f"| Advisory Fix Known | {bd.get('advisory', 0)} / 10 |",
        f"| Scanner Confirmed | {bd.get('scanner', 0)} / 5 |",
        "",
        "### Test Results",
        "",
        "| | Before | After |",
        "|---|---|---|",
        f"| Passed | {pre.passed if pre else '—'} | {post.passed if post else '—'} |",
        f"| Failed | {pre.failed if pre else '—'} | {post.failed if post else '—'} |",
        f"| Result | — | {'✅ No regressions' if state.test_delta_passed else '⚠️ Not verified'} |",
        "",
        f"### Breaking Change Risk: {sanitize_markdown(state.breaking_change_risk or 'unknown')}",
        "",
    ]
    if notes:
        lines += [sanitize_markdown(notes), ""]
    if state.fix_attempt > 1:
        lines += [f"_Validated on fix attempt {state.fix_attempt} after earlier attempts failed validation._", ""]
    lines += ["---", ""]
    if state.confluence_page_url:
        lines.append(f"📄 **Audit Trail:** {state.confluence_page_url}")
        lines.append("")
    if state.jira_issue_key:
        lines.append(f"🎫 **JIRA:** {one_line(state.jira_issue_key, 40)}")
        lines.append("")
    lines += [
        f"🔍 **Graph Trace:** {control_api_url.rstrip('/')}/api/v1/jobs/{state.job_id}/graph-trace",
        "",
        f"🤖 **Job ID:** `{state.job_id}`",
        "",
        pr_marker(state),
    ]
    return "\n".join(lines)
