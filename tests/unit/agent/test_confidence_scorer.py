import pytest

from src.agent.nodes.confidence_scorer import classify_fix, score_confidence
from src.agent.state import FileChange


def fc(path: str) -> FileChange:
    return FileChange(file_path=path, original_content="a", new_content="b", change_description="x")


def ctx(verified: bool = True) -> dict:
    return {"cve": {"advisory_fix_verified": verified}}


@pytest.mark.parametrize(
    "paths,expected",
    [
        (["requirements.txt"], ("version_bump", 25)),
        (["backend/requirements-dev.txt", "constraints.txt"], ("version_bump", 25)),
        (["package.json", "package-lock.json"], ("version_bump", 25)),
        (["go.mod", "go.sum"], ("version_bump", 25)),
        (["src/App/App.csproj"], ("version_bump", 25)),
        (["pyproject.toml"], ("version_bump", 25)),
        (["requirements.txt", "config/settings.yaml"], ("config_change", 15)),
        (["config/app.json"], ("config_change", 15)),
        (["app/client.py"], ("code_rewrite", 5)),
        (["requirements.txt", "app/client.py"], ("code_rewrite", 5)),
    ],
)
def test_classify_fix(paths, expected):
    assert classify_fix([fc(p) for p in paths], "requirements.txt") == expected


def test_declared_manifest_always_counts_as_manifest():
    assert classify_fix([fc("weird/deps.lst")], "weird/deps.lst") == ("version_bump", 25)


async def test_max_partial_score_is_70(make_state):
    state = make_state(
        cvss_score=10.0, llm_self_confidence=100, file_changes=[fc("requirements.txt")], context_payload=ctx()
    )
    out = await score_confidence(state)
    assert out["confidence_score"] == 70
    assert out["confidence_breakdown"] == {
        "severity": 20, "simplicity": 25, "simplicity_class": "version_bump", "llm_certainty": 15,
        "advisory": 10, "tests": 0, "scanner": 0, "partial": True,
    }  # fmt: skip
    assert out["audit_events"][-1]["event_type"] == "CONFIDENCE_SCORED"


async def test_components_scale(make_state):
    state = make_state(
        cvss_score=5.6, llm_self_confidence=85, file_changes=[fc("app/client.py")], context_payload=ctx(False)
    )
    out = await score_confidence(state)
    b = out["confidence_breakdown"]
    assert (b["severity"], b["simplicity"], b["llm_certainty"], b["advisory"]) == (11, 5, 13, 0)
    assert out["confidence_score"] == 29


async def test_clamps_out_of_range_inputs(make_state):
    state = make_state(
        cvss_score=14.0, llm_self_confidence=400, file_changes=[fc("requirements.txt")], context_payload=ctx()
    )
    b = (await score_confidence(state))["confidence_breakdown"]
    assert b["severity"] == 20 and b["llm_certainty"] == 15


async def test_missing_self_confidence_scores_zero(make_state):
    state = make_state(file_changes=[fc("requirements.txt")], context_payload=ctx())
    assert (await score_confidence(state))["confidence_breakdown"]["llm_certainty"] == 0


async def test_noop_on_upstream_error_or_no_changes(make_state):
    assert await score_confidence(make_state(error="boom", file_changes=[fc("requirements.txt")])) == {}
    assert await score_confidence(make_state()) == {}
