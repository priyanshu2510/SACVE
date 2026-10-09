import pytest

from src.agent import routing as r


def test_route_after_context(make_state):
    assert r.route_after_context(make_state()) == "assess_reachability"
    assert r.route_after_context(make_state(error="boom")) == "handle_error"


def test_route_after_reachability(make_state):
    assert r.route_after_reachability(make_state()) == "generate_fix"
    assert r.route_after_reachability(make_state(terminal_status="NOT_REACHABLE")) == "write_audit"
    assert r.route_after_reachability(make_state(error="x")) == "handle_error"
    # advisory mode: unreachable is annotated but the job still proceeds
    assert r.route_after_reachability(make_state(reachable=False)) == "generate_fix"


def test_route_after_fix(make_state):
    assert r.route_after_fix(make_state()) == "score_confidence"
    assert r.route_after_fix(make_state(error="llm down")) == "handle_error"


@pytest.mark.parametrize(
    "score,error,expected",
    [(70, None, "run_sandbox"), (20, None, "run_sandbox"), (19, None, "handle_error"),
     (None, None, "handle_error"), (70, "boom", "handle_error")],
)  # fmt: skip
def test_route_after_scoring(make_state, score, error, expected):
    assert r.route_after_scoring(make_state(confidence_score=score, error=error)) == expected


def test_route_after_scoring_reuses_existing_sandbox(make_state):
    assert r.route_after_scoring(make_state(confidence_score=60, sandbox_container_id="abc")) == "apply_patch"
    assert r.route_after_scoring(make_state(confidence_score=10, sandbox_container_id="abc")) == "handle_error"


def test_route_after_sandbox(make_state):
    assert r.route_after_sandbox(make_state()) == "run_pre_tests"
    assert r.route_after_sandbox(make_state(terminal_status="BASELINE_FAILING")) == "cleanup_sandbox"
    assert r.route_after_sandbox(make_state(error="docker down")) == "handle_error"


def test_route_after_pre_tests(make_state):
    assert r.route_after_pre_tests(make_state()) == "apply_patch"
    assert r.route_after_pre_tests(make_state(terminal_status="BASELINE_FAILING")) == "cleanup_sandbox"
    assert r.route_after_pre_tests(make_state(terminal_status="NO_TESTS")) == "cleanup_sandbox"
    assert r.route_after_pre_tests(make_state(error="docker")) == "handle_error"


@pytest.mark.parametrize(
    "router,ok",
    [(r.route_after_patch, "resolve_dependencies"), (r.route_after_resolve, "run_post_tests"), (r.route_after_post_tests, "run_security_scan"),
     (r.route_after_scan, "cleanup_sandbox")],
)  # fmt: skip
def test_repair_loop_routers(make_state, router, ok):
    assert router(make_state(fix_attempt=1)) == ok
    # failure with attempts left -> retry; max_fix_attempts=3
    assert router(make_state(fix_attempt=1, failure_reason="regression")) == "generate_fix"
    assert router(make_state(fix_attempt=2, failure_reason="regression")) == "generate_fix"
    # attempts exhausted -> BLOCKED path through cleanup
    assert router(make_state(fix_attempt=3, failure_reason="regression")) == "cleanup_sandbox"
    assert router(make_state(fix_attempt=5, failure_reason="regression")) == "cleanup_sandbox"
    # hard errors never retry
    assert router(make_state(fix_attempt=1, error="boom", failure_reason="x")) == "handle_error"


def test_repair_loop_respects_configured_limit(make_state):
    assert r.route_after_post_tests(make_state(fix_attempt=1, max_fix_attempts=1, failure_reason="x")) == "cleanup_sandbox"
    assert r.route_after_post_tests(make_state(fix_attempt=1, max_fix_attempts=2, failure_reason="x")) == "generate_fix"


def test_route_after_cleanup(make_state):
    good = {"test_delta_passed": True, "scanner_cve_resolved": True}
    assert r.route_after_cleanup(make_state(**good)) == "create_pr"
    assert r.route_after_cleanup(make_state(**good, terminal_status="BLOCKED")) == "write_audit"
    assert r.route_after_cleanup(make_state(**good, terminal_status="FAILED", error="x")) == "write_audit"
    assert r.route_after_cleanup(make_state(**good, failure_reason="still vulnerable")) == "write_audit"
    assert r.route_after_cleanup(make_state(test_delta_passed=True)) == "write_audit"
    assert r.route_after_cleanup(make_state(scanner_cve_resolved=True)) == "write_audit"
    assert r.route_after_cleanup(make_state()) == "write_audit"


def test_route_after_pr(make_state):
    assert r.route_after_pr(make_state(terminal_status="PR_RAISED")) == "notify_owners"
    assert r.route_after_pr(make_state(terminal_status="PR_EXISTS")) == "write_audit"  # nothing new to announce
    assert r.route_after_pr(make_state(error="boom")) == "handle_error"
