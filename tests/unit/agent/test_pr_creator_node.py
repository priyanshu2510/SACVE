from datetime import datetime, timezone

import pytest

from src.agent.deps import override_deps
from src.agent.nodes.pr_creator import branch_name, create_pr
from src.agent.state import FileChange, TestResult
from src.services.github.pr_creator import ExistingPR, PRConflictError
from tests.fakes import FakePRService, MemoryIdempotency

async def _defaults():
    return 85, 70


JOB = "11111111-2222-3333-4444-555555555555"


def ready(make_state, **kw):
    base = dict(
        job_id=JOB, fix_attempt=1, confidence_score=90, test_delta_passed=True, scanner_cve_resolved=True,
        llm_explanation="Bump.", breaking_change_risk="low",
        file_changes=[FileChange(file_path="requirements.txt", original_content="requests==2.31.0", new_content="requests==2.32.0", change_description="bump")],
        pre_fix_tests=TestResult(total=1, passed=1, failed=0, skipped=0, stdout=""),
    )  # fmt: skip
    return make_state(**(base | kw))


async def run(state, pr=None, idem=None):
    pr, idem = pr or FakePRService(), idem or MemoryIdempotency()
    with override_deps(pr_service=pr, idempotency=idem, tier_thresholds=_defaults):
        return pr, idem, await create_pr(state)


def test_branch_name(make_state):
    day = datetime(2026, 10, 9, tzinfo=timezone.utc)
    assert branch_name(make_state(repo_name="org/api-gateway"), day) == "fix/cve-CVE-2024-35195-api-gateway-20261009"
    assert branch_name(make_state(repo_name="org/we ird..name!"), day) == "fix/cve-CVE-2024-35195-we-ird..name-20261009"


def test_branch_name_rejects_malformed_cve(make_state):
    from src.agent.nodes._common import NodeError

    with pytest.raises(NodeError):
        branch_name(make_state(cve_id="CVE-1; rm -rf /"))


async def test_raises_pr_with_owners_labels_and_body(make_state):
    pr, idem, out = await run(ready(make_state))
    assert out["terminal_status"] == "PR_RAISED" and out["pr_number"] == 101
    assert out["pr_url"] == "https://github.com/org/api-gateway/pull/101" and out["branch_name"].startswith("fix/cve-CVE-2024-35195-api-gateway-")
    assert out["code_owners"] == ["@alice", "@org/platform"]
    (call,) = pr.created
    assert call["users"] == ["alice"] and call["teams"] == ["org/platform"]  # split for review requests
    assert call["labels"] == ["security", "cve-fix", "automated", "severity:medium"]
    assert call["title"].startswith("fix(medium): CVE-2024-35195") and f"job_id={JOB}" in call["body"]
    assert "CVE-2024-35195" in call["commit_message"] and JOB in call["commit_message"]
    assert pr.paths == ["requirements.txt"]
    event = out["audit_events"][-1]
    assert event["event_type"] == "PR_RAISED" and event["payload"]["branch_protection"]["protected"] is True
    assert idem.data[f"create_pr:{JOB}"]["number"] == 101


async def test_replay_does_not_create_a_second_pr(make_state):
    pr, idem, first = await run(ready(make_state))
    _, _, second = await run(ready(make_state), pr=pr, idem=idem)
    assert len(pr.created) == 1 and second["pr_url"] == first["pr_url"] and second["terminal_status"] == "PR_RAISED"
    assert second["audit_events"][-1]["payload"]["replayed"] is True


async def test_open_pr_from_another_job_is_deduplicated(make_state):
    existing = ExistingPR("https://github.com/org/api-gateway/pull/5", 5, "fix/cve-CVE-2024-35195-api-gateway-20261001", "other-job")
    pr, _, out = await run(ready(make_state), pr=FakePRService(existing=existing))
    assert pr.created == [] and out["terminal_status"] == "PR_EXISTS" and out["pr_number"] == 5
    assert out["audit_events"][-1]["event_type"] == "PR_DEDUPLICATED"


async def test_open_pr_from_same_job_is_recovered_after_a_crash(make_state):
    existing = ExistingPR("https://github.com/org/api-gateway/pull/5", 5, "fix/cve-x", JOB)
    pr, idem, out = await run(ready(make_state), pr=FakePRService(existing=existing))
    assert pr.created == [] and out["terminal_status"] == "PR_RAISED" and idem.data[f"create_pr:{JOB}"]["number"] == 5


async def test_base_branch_moved_is_an_error(make_state):
    out = (await run(ready(make_state), pr=FakePRService(create_error=PRConflictError("found 0 matches"))))[2]
    assert out["terminal_status"] == "FAILED" and "cannot raise PR: found 0 matches" in out["error"]


async def test_warnings_are_carried_to_state(make_state):
    out = (await run(ready(make_state), pr=FakePRService(warnings=["could not request review from @bob: HTTP 422"])))[2]
    assert out["pr_warnings"] == ["could not request review from @bob: HTTP 422"]


async def test_requires_changes(make_state):
    out = (await run(make_state()))[2]
    assert "requires file changes" in out["error"]
