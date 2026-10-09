import pytest

from src.agent.deps import override_deps
from src.agent.nodes import test_runner as tr
from src.agent.nodes.test_runner import parse_pytest_output, run_post_tests, run_pre_tests
from src.agent.state import FileChange, TestResult
from tests.fakes import PASSING, FakeSandboxManager, failing


@pytest.mark.parametrize(
    "output,expected",
    [
        ("....\n4 passed in 0.12s\n", (4, 4, 0, 0)),
        ("..F\nFAILED tests/t.py::test_a - assert 0\n1 failed, 2 passed in 0.5s\n", (3, 2, 1, 0)),
        ("3 passed, 2 skipped, 1 warning in 1.00s", (5, 3, 0, 2)),
        ("ERROR tests/t.py - ImportError\n1 error in 0.1s\n", (1, 0, 1, 0)),
        ("2 failed, 1 error, 5 passed in 3.2s", (8, 5, 3, 0)),
        ("============ 1 failed, 9 passed in 2.00s ============", (10, 9, 1, 0)),
        ("no tests ran in 0.01s", (0, 0, 0, 0)),
        ("", (0, 0, 0, 0)),
        ("random garbage", (0, 0, 0, 0)),
    ],
)
def test_parse_counts(output, expected):
    r = parse_pytest_output(output)
    assert (r.total, r.passed, r.failed, r.skipped) == expected


def test_parse_failed_names_deduplicated():
    out = "FAILED tests/a.py::t1 - x\nERROR tests/b.py::t2\nFAILED tests/a.py::t1 - x\n2 failed in 1s\n"
    assert parse_pytest_output(out).failed_test_names == ["tests/a.py::t1", "tests/b.py::t2"]


async def state_with_sandbox(make_state, **sandbox_kw):
    mgr = FakeSandboxManager({"requirements.txt": "requests==2.31.0\n"}, **sandbox_kw)
    sb = await mgr.create(job_id="j", repo_name="o/r", ecosystem="pip")
    return mgr, sb, make_state(sandbox_container_id=sb.container_id, fix_attempt=1,
                               confidence_score=60, confidence_breakdown={"tests": 0})  # fmt: skip


async def test_pre_tests_pass(make_state):
    mgr, sb, state = await state_with_sandbox(make_state)
    with override_deps(sandbox_manager=mgr):
        out = await run_pre_tests(state)
    assert out["pre_fix_tests"].passed == 4 and "terminal_status" not in out
    assert out["audit_events"][-1]["event_type"] == "PRE_TESTS_PASSED"
    assert any("pytest" in c for c in sb.calls[0])


async def test_pre_tests_failing_baseline(make_state):
    mgr, _, state = await state_with_sandbox(make_state, pytest_outputs=[failing("test_a", "test_b")])
    with override_deps(sandbox_manager=mgr):
        out = await run_pre_tests(state)
    assert out["terminal_status"] == "BASELINE_FAILING" and out["pre_fix_tests"].failed == 2
    assert out["audit_events"][-1]["payload"]["failed_tests"] == ["tests/test_app.py::test_a", "tests/test_app.py::test_b"]


async def test_pre_tests_no_tests_found(make_state, monkeypatch):
    mgr, _, state = await state_with_sandbox(make_state, pytest_outputs=["no tests ran in 0.01s"])
    with override_deps(sandbox_manager=mgr):
        assert (await run_pre_tests(state))["terminal_status"] == "NO_TESTS"
        monkeypatch.setattr(tr.settings, "REQUIRE_TESTS", False)
        out = await run_pre_tests(state)
    assert "terminal_status" not in out and out["audit_events"][-1]["event_type"] == "PRE_TESTS_PASSED"


async def test_pre_tests_without_sandbox_is_error(make_state):
    out = await run_pre_tests(make_state())
    assert "no sandbox" in out["error"]


async def post_state(make_state, mgr, sb, passed=4):
    return make_state(
        sandbox_container_id=sb.container_id, fix_attempt=1, confidence_score=60, confidence_breakdown={"tests": 0},
        pre_fix_tests=TestResult(total=passed, passed=passed, failed=0, skipped=0, stdout=""),
        file_changes=[FileChange(file_path="requirements.txt", original_content="a", new_content="b", change_description="bump")],
    )  # fmt: skip


async def test_post_tests_pass_adds_test_points(make_state):
    mgr, sb, _ = await state_with_sandbox(make_state)
    state = await post_state(make_state, mgr, sb)
    with override_deps(sandbox_manager=mgr):
        out = await run_post_tests(state)
    assert out["test_delta_passed"] is True and out["confidence_score"] == 85
    assert out["confidence_breakdown"]["tests"] == 25 and "failure_reason" not in out


async def test_post_tests_regression_is_repairable_failure(make_state):
    mgr, sb, _ = await state_with_sandbox(make_state, pytest_outputs=[failing("test_login", passed=3)])
    state = await post_state(make_state, mgr, sb)
    with override_deps(sandbox_manager=mgr):
        out = await run_post_tests(state)
    assert out["test_delta_passed"] is False and out["post_fix_tests"].failed == 1
    assert "test_login" in out["failure_reason"]
    (attempt,) = out["previous_attempts"]
    assert attempt["fix_attempt"] == 1 and attempt["file_changes"][0]["file_path"] == "requirements.txt"
    assert [e["event_type"] for e in out["audit_events"][-2:]] == ["POST_TESTS_FAILED", "FIX_ATTEMPT_FAILED"]
    assert "confidence_score" not in out  # no test points for a regression


async def test_post_tests_lost_passing_tests_count_as_regression(make_state):
    mgr, sb, _ = await state_with_sandbox(make_state, pytest_outputs=["2 passed in 0.1s"])
    state = await post_state(make_state, mgr, sb, passed=4)
    with override_deps(sandbox_manager=mgr):
        out = await run_post_tests(state)
    assert out["test_delta_passed"] is False and "only 2 tests pass" in out["failure_reason"]


async def test_post_tests_requires_baseline(make_state):
    mgr, sb, state = await state_with_sandbox(make_state)
    with override_deps(sandbox_manager=mgr):
        out = await run_post_tests(state)
    assert "requires pre_fix_tests" in out["error"]
