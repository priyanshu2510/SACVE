import pytest

from src.agent.state import TestResult
from src.services.github.pr_description import (
    MARKER_RE, ZWSP, confidence_tier, one_line, pr_marker, pr_title, render_pr_body, sanitize_markdown,
)  # fmt: skip


@pytest.mark.parametrize("score,label", [(100, "HIGH"), (85, "HIGH"), (84, "MEDIUM"), (70, "MEDIUM"), (69, "LOW"), (0, "LOW")])
def test_tiers(score, label):
    assert confidence_tier(score).label == label


def test_sanitize_neutralises_mentions_html_refs_and_images():
    out = sanitize_markdown("ping @octocat and @org/team, see #123 <script>x</script> ![t](http://evil/p.png) a&b me@x.com")
    assert f"@{ZWSP}octocat" in out and f"@{ZWSP}org/team" in out
    assert f"#{ZWSP}123" in out and "<script>" not in out and "&lt;script>" in out
    assert f"!{ZWSP}[t]" in out and "a&amp;b" in out
    assert "me@x.com" in out  # email addresses are untouched


def test_one_line_collapses_and_escapes_table_pipes():
    assert one_line("a\n b | c") == "a b \\| c"
    assert len(one_line("x" * 500)) == 200


def full_state(make_state, **kw):
    base = dict(
        job_id="11111111-2222-3333-4444-555555555555", fix_attempt=1, confidence_score=90,
        confidence_breakdown={"severity": 11, "simplicity": 25, "llm_certainty": 14, "advisory": 10, "tests": 25, "scanner": 5},
        llm_explanation="Bump requests to 2.32.0.", breaking_change_risk="low", test_delta_passed=True,
        pre_fix_tests=TestResult(total=4, passed=4, failed=0, skipped=0, stdout=""),
        post_fix_tests=TestResult(total=4, passed=4, failed=0, skipped=0, stdout=""),
    )  # fmt: skip
    return make_state(**(base | kw))


def test_title(make_state):
    assert pr_title(make_state()) == "fix(medium): CVE-2024-35195 bump requests 2.31.0 → 2.32.0"


def test_body_follows_template(make_state):
    body = render_pr_body(full_state(make_state), "https://control.example.com/")
    for needle in [
        "## 🔒 Security Fix: CVE-2024-35195 (MEDIUM, CVSS 5.6)", "[CVE-2024-35195](https://nvd.nist.gov/vuln/detail/CVE-2024-35195)",
        "| Fix | `2.31.0` → `2.32.0` |", "### Confidence Score: 90 / 100", "**HIGH**", "| CVE Severity | 11 / 20 |",
        "| Fix Simplicity | 25 / 25 |", "| LLM Certainty | 14 / 15 |", "| Test Pass Rate | 25 / 25 |",
        "| Advisory Fix Known | 10 / 10 |", "| Scanner Confirmed | 5 / 5 |", "| Passed | 4 | 4 |", "✅ No regressions",
        "### Breaking Change Risk: low",
        "🔍 **Graph Trace:** https://control.example.com/api/v1/jobs/11111111-2222-3333-4444-555555555555/graph-trace",
        "🤖 **Job ID:** `11111111-2222-3333-4444-555555555555`",
    ]:  # fmt: skip
        assert needle in body, needle
    assert "JIRA" not in body and "Audit Trail" not in body and "Reachability" not in body  # absent until available


def test_body_optional_sections(make_state):
    state = full_state(make_state, jira_issue_key="SEC-1", confluence_page_url="https://wiki/p/1", reachable=False,
                       reachability_evidence={"reason": "no imports"}, breaking_change_notes="API removed @everyone", fix_attempt=2)  # fmt: skip
    body = render_pr_body(state, "https://c")
    assert "SEC-1" in body and "https://wiki/p/1" in body and "no imports" in body
    assert "attempt 2" in body and f"@{ZWSP}everyone" in body


def test_marker_roundtrip(make_state):
    state = full_state(make_state)
    m = MARKER_RE.search(render_pr_body(state, "https://c"))
    assert m.group("job") == state.job_id and m.group("cve") == "CVE-2024-35195"
    assert MARKER_RE.search(pr_marker(state))


def test_untrusted_explanation_cannot_break_out(make_state):
    body = render_pr_body(full_state(make_state, llm_explanation="</details><img src=x onerror=alert(1)> @all"), "https://c")
    assert "<img" not in body and "&lt;/details>" in body and f"@{ZWSP}all" in body
