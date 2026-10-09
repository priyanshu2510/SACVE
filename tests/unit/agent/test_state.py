from src.agent.state import AgentState, FileChange, TestResult


def test_defaults(make_state):
    s = make_state()
    assert s.fix_attempt == 0 and s.previous_attempts == [] and s.audit_events == []
    assert s.error is None and s.terminal_status is None and s.failure_reason is None
    assert s.max_fix_attempts == 3 and s.ecosystem == "pip"


def test_mutable_defaults_are_not_shared(make_state):
    a, b = make_state(), make_state()
    a.audit_events.append({"x": 1})
    a.previous_attempts.append({"y": 2})
    assert b.audit_events == [] and b.previous_attempts == []


def test_roundtrip_with_nested_models(make_state):
    s = make_state(
        file_changes=[FileChange(file_path="requirements.txt", original_content="a", new_content="b", change_description="bump")],
        pre_fix_tests=TestResult(total=2, passed=2, failed=0, skipped=0, stdout="ok"),
    )  # fmt: skip
    again = AgentState(**s.model_dump())
    assert again == s and again.file_changes[0].file_path == "requirements.txt"
    assert again.pre_fix_tests.failed_test_names == []
