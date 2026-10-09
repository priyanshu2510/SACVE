import pytest

from src.agent.deps import override_deps
from src.agent.nodes.dependency_resolver import resolve_dependencies
from src.agent.state import FileChange
from src.services.sandbox.base import ExecResult
from tests.fakes import FakeSandboxManager

PATCHED = "flask==3.0.0\nrequests==2.32.0\n"


async def run(make_state, files=None, **sandbox_kw):
    mgr = FakeSandboxManager(files or {"requirements.txt": PATCHED}, **sandbox_kw)
    sb = await mgr.create(job_id="j", repo_name="o/r", ecosystem="pip")
    state = make_state(
        sandbox_container_id=sb.container_id, fix_attempt=1,
        file_changes=[FileChange(file_path="requirements.txt", original_content="a", new_content="b", change_description="x")],
    )  # fmt: skip
    with override_deps(sandbox_manager=mgr):
        return sb, await resolve_dependencies(state)


async def test_success_reports_version_and_changed_files(make_state):
    sb, out = await run(make_state)
    assert "failure_reason" not in out and out["lockfile_changes"] == []
    assert out["audit_events"][-1]["payload"]["resolved_version"] == "2.32.0"
    install = next(c for c in sb.calls if c[1:2] == ["install"])
    assert install[:4] == ["/opt/venv/bin/pip", "install", "-r", "requirements.txt"] and install[-1] == "pytest"


async def test_install_failure_is_repairable(make_state):
    _, out = await run(make_state, install_results=[ExecResult(1, "ERROR: ResolutionImpossible: conflict")])
    assert "installation failed" in out["failure_reason"] and "ResolutionImpossible" in out["failure_reason"]
    assert "ResolutionImpossible" in out["dependency_resolution_output"]


async def test_timeout_is_reported(make_state):
    _, out = await run(make_state, install_results=[ExecResult(124, "", timed_out=True)])
    assert "timed out" in out["failure_reason"]


async def test_resolved_below_target_is_repairable(make_state):
    # the "patched" manifest still pins the old version
    _, out = await run(make_state, files={"requirements.txt": "requests==2.31.0\n"})
    assert "resolved to 2.31.0, below the required 2.32.0" in out["failure_reason"]


async def test_package_missing_after_install(make_state):
    _, out = await run(make_state, files={"requirements.txt": "flask==3.0.0\n"})
    assert "resolved to nothing" in out["failure_reason"]


async def test_network_disabled_is_a_config_error_not_a_retry(make_state):
    _, out = await run(make_state, network_enabled=False)
    assert "network disabled" in out["error"] and "failure_reason" not in out


async def test_unsupported_manifest_is_an_error(make_state):
    mgr = FakeSandboxManager({"Pipfile": ""})
    sb = await mgr.create(job_id="j", repo_name="o/r", ecosystem="pip")
    with override_deps(sandbox_manager=mgr):
        out = await resolve_dependencies(make_state(sandbox_container_id=sb.container_id, manifest_file_path="Pipfile"))
    assert "unsupported pip manifest" in out["error"]


@pytest.mark.parametrize(
    "manifest,expected",
    [("pyproject.toml", ["/opt/venv/bin/pip", "install", ".", "pytest"]),
     ("sub/requirements.txt", ["/opt/venv/bin/pip", "install", "-r", "sub/requirements.txt", "pytest"])],
)  # fmt: skip
async def test_install_command_by_manifest(make_state, manifest, expected):
    mgr = FakeSandboxManager({manifest: "requests==2.32.0\n"})
    sb = await mgr.create(job_id="j", repo_name="o/r", ecosystem="pip")
    with override_deps(sandbox_manager=mgr):
        await resolve_dependencies(make_state(sandbox_container_id=sb.container_id, manifest_file_path=manifest))
    assert next(c for c in sb.calls if c[1:2] == ["install"]) == expected


async def test_dev_requirements_are_installed_too(make_state):
    files = {"requirements.txt": PATCHED, "requirements-dev.txt": "pytest-mock\n"}
    sb, _ = await run(make_state, files=files)
    install = next(c for c in sb.calls if c[1:2] == ["install"])
    assert "requirements-dev.txt" in install
