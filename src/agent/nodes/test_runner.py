"""Nodes 6 + 8: run the repo's test suite before and after the patch."""

from __future__ import annotations

import re
from typing import Any

from src.agent.deps import get_sandbox_manager
from src.agent.nodes import _pip
from src.agent.nodes._common import NodeError, agent_node, make_event, record_failure
from src.agent.routing import BASELINE_FAILING
from src.agent.state import AgentState, TestResult
from src.core.config import settings
from src.services.sandbox.base import Sandbox, tail

NO_TESTS = "NO_TESTS"
TESTS_SCORE_MAX = 25

_COUNT = re.compile(r"(\d+) (passed|failed|skipped|errors?|xfailed|xpassed|deselected|warnings?)")
_SUMMARY = re.compile(r"\bin \d+(?:\.\d+)?s\b")
_FAILED_LINE = re.compile(r"^(?:FAILED|ERROR) (\S+)", re.MULTILINE)


def parse_pytest_output(output: str) -> TestResult:
    """Parse pytest's ``-q -rfE`` output. Collection errors / ``ERROR`` entries count as failures."""
    counts = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
    for line in reversed(output.strip().splitlines()):
        if _SUMMARY.search(line) or line.strip().startswith("no tests ran"):
            for n, kind in _COUNT.findall(line):
                kind = "error" if kind.startswith("error") else kind
                if kind in counts:
                    counts[kind] += int(n)
            break
    failed = counts["failed"] + counts["error"]
    names = list(dict.fromkeys(_FAILED_LINE.findall(output)))
    return TestResult(
        total=counts["passed"] + failed + counts["skipped"],
        passed=counts["passed"],
        failed=failed,
        skipped=counts["skipped"],
        stdout=tail(output),
        failed_test_names=names,
    )


async def _run_pytest(sandbox: Sandbox) -> tuple[TestResult, bool]:
    res = await sandbox.exec(
        [_pip.PYTHON, "-m", "pytest", "--tb=short", "-q", "-rfE", "-p", "no:cacheprovider"],
        timeout=settings.SANDBOX_TIMEOUT_SECONDS,
    )
    return parse_pytest_output(res.output), res.timed_out


async def _attach(state: AgentState) -> Sandbox:
    if not state.sandbox_container_id:
        raise NodeError("no sandbox is running for this job")
    return await get_sandbox_manager().attach(state.sandbox_container_id)


@agent_node("run_pre_tests")
async def run_pre_tests(state: AgentState) -> dict[str, Any]:
    """Run the suite on the untouched checkout. Failing tests (or none at all) end the job early."""
    result, timed_out = await _run_pytest(await _attach(state))
    if timed_out:
        raise NodeError("baseline test run timed out")
    payload = {"total": result.total, "passed": result.passed, "failed": result.failed, "skipped": result.skipped}
    if result.failed > 0:
        return {
            "pre_fix_tests": result,
            "terminal_status": BASELINE_FAILING,
            "audit_events": [*state.audit_events, make_event("PRE_TESTS_FAILED", payload | {"failed_tests": result.failed_test_names[:50]})],
        }  # fmt: skip
    if result.total == 0 and settings.REQUIRE_TESTS:
        return {
            "pre_fix_tests": result,
            "terminal_status": NO_TESTS,
            "audit_events": [*state.audit_events, make_event("PRE_TESTS_FAILED", payload | {"reason": "no tests found"})],
        }  # fmt: skip
    return {
        "pre_fix_tests": result,
        "audit_events": [*state.audit_events, make_event("PRE_TESTS_PASSED", payload)],
    }


@agent_node("run_post_tests")
async def run_post_tests(state: AgentState) -> dict[str, Any]:
    """Re-run the suite on the patched checkout; any new failure (or lost passing test) is a regression."""
    pre = state.pre_fix_tests
    if pre is None:
        raise NodeError("run_post_tests requires pre_fix_tests")
    result, timed_out = await _run_pytest(await _attach(state))
    payload = {"total": result.total, "passed": result.passed, "failed": result.failed, "skipped": result.skipped}

    regressed = timed_out or result.failed > 0 or result.passed < pre.passed
    if not regressed:
        breakdown = dict(state.confidence_breakdown or {})
        tests_points = round(TESTS_SCORE_MAX * min(1.0, result.passed / pre.passed)) if pre.passed else TESTS_SCORE_MAX
        breakdown["tests"] = tests_points
        return {
            "post_fix_tests": result,
            "test_delta_passed": True,
            "confidence_score": (state.confidence_score or 0) + tests_points,
            "confidence_breakdown": breakdown,
            "audit_events": [*state.audit_events, make_event("POST_TESTS_PASSED", payload)],
        }

    if timed_out:
        reason = "the test suite timed out after applying the fix"
    elif result.failed:
        reason = f"{result.failed} test(s) fail after the fix (they passed before): {', '.join(result.failed_test_names[:20])}"
    else:
        reason = f"only {result.passed} tests pass after the fix versus {pre.passed} before"
    failure = record_failure(
        state,
        f"{reason}\n--- test output (tail) ---\n{tail(result.stdout, 3000)}",
        events=[("POST_TESTS_FAILED", payload | {"failed_tests": result.failed_test_names[:50], "timed_out": timed_out})],
    )
    return failure | {"post_fix_tests": result, "test_delta_passed": False}
