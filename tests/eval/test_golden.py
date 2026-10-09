"""pytest entry point for the golden evaluation: ``pytest -m eval tests/eval`` (excluded from the default run)."""

import pytest

from tests.eval.harness import evaluate_gate, load_cases, render_report, run_case

pytestmark = pytest.mark.eval
CASES = load_cases()
_results: dict[str, object] = {}


@pytest.fixture(scope="module", autouse=True)
def _docker_and_image():
    import docker

    try:
        client = docker.from_env()
        client.ping()
        client.images.get("cve-sandbox-python:latest")
    except Exception:  # noqa: BLE001
        pytest.skip("Docker or the cve-sandbox-python image is not available")


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_golden_case(case):
    result = await run_case(case, "replay")
    _results[case.name] = result
    failed = [f"{c.name}: {c.detail}" for c in result.checks if not c.ok]
    assert result.passed, f"{case.name} ({result.terminal_status}): {failed}"


def test_release_gate():
    results = [_results[c.name] for c in CASES if c.name in _results]
    if len(results) != len(CASES):
        pytest.skip("not every case ran (deselected?), gate not evaluated")
    gate = evaluate_gate(results, "replay")
    assert gate.passed, "\n" + render_report(results, gate)
