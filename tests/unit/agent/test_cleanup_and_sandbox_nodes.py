from src.agent.deps import override_deps
from src.agent.nodes.cleanup_sandbox import cleanup_sandbox
from src.agent.nodes.sandbox_executor import run_sandbox
from src.services.sandbox.base import ExecResult, SandboxError
from tests.fakes import FakeSandboxManager

FILES = {"requirements.txt": "requests==2.31.0\n"}


# ---------------------------------------------------------------- cleanup_sandbox
async def test_cleanup_removes_container_and_blocks_exhausted_jobs(make_state):
    mgr = FakeSandboxManager(FILES)
    sb = await mgr.create(job_id="j", repo_name="o/r", ecosystem="pip")
    with override_deps(sandbox_manager=mgr):
        out = await cleanup_sandbox(make_state(sandbox_container_id=sb.container_id, failure_reason="3 tests fail", fix_attempt=3))
    assert mgr.removed == [sb.container_id] and out["sandbox_container_id"] is None
    assert out["terminal_status"] == "BLOCKED"
    assert [e["event_type"] for e in out["audit_events"]] == ["SANDBOX_REMOVED", "JOB_BLOCKED"]


async def test_cleanup_preserves_specific_terminal_status(make_state):
    mgr = FakeSandboxManager(FILES)
    sb = await mgr.create(job_id="j", repo_name="o/r", ecosystem="pip")
    with override_deps(sandbox_manager=mgr):
        out = await cleanup_sandbox(make_state(sandbox_container_id=sb.container_id, terminal_status="BASELINE_FAILING"))
    assert "terminal_status" not in out


async def test_cleanup_without_container_is_a_noop_for_docker(make_state):
    mgr = FakeSandboxManager(FILES)
    with override_deps(sandbox_manager=mgr):
        out = await cleanup_sandbox(make_state(terminal_status="FAILED", error="x"))
    assert mgr.removed == [] and "sandbox_container_id" not in out


async def test_cleanup_never_raises_when_removal_fails(make_state):
    class Broken(FakeSandboxManager):
        async def remove(self, container_id):
            raise RuntimeError("docker daemon went away")

    with override_deps(sandbox_manager=Broken(FILES)):
        out = await cleanup_sandbox(make_state(sandbox_container_id="abc123abc123", terminal_status="FAILED"))
    assert out["sandbox_container_id"] is None and "docker daemon" in out["audit_events"][-1]["payload"]["error"]


# ---------------------------------------------------------------- run_sandbox
async def test_run_sandbox_starts_and_installs_baseline(make_state):
    mgr = FakeSandboxManager(FILES)
    with override_deps(sandbox_manager=mgr):
        out = await run_sandbox(make_state())
    assert out["sandbox_container_id"] == mgr.only.container_id and "terminal_status" not in out
    assert out["audit_events"][-1]["event_type"] == "SANDBOX_STARTED"
    assert mgr.only.installed == {"requests": "2.31.0"}


async def test_baseline_install_failure_is_baseline_failing(make_state):
    mgr = FakeSandboxManager(FILES, install_results=[ExecResult(1, "ERROR: no matching distribution")])
    with override_deps(sandbox_manager=mgr):
        out = await run_sandbox(make_state())
    assert out["terminal_status"] == "BASELINE_FAILING" and out["sandbox_container_id"]
    assert [e["event_type"] for e in out["audit_events"]] == ["SANDBOX_STARTED", "PRE_TESTS_FAILED"]


async def test_network_disabled_removes_the_container_and_explains(make_state):
    mgr = FakeSandboxManager(FILES, network_enabled=False)
    with override_deps(sandbox_manager=mgr):
        out = await run_sandbox(make_state())
    assert "sandbox_container_id" not in out and out["terminal_status"] == "FAILED"
    assert "network disabled" in out["error"] and mgr.removed == [mgr.only.container_id]


async def test_unexpected_failure_after_create_does_not_leak_the_container(make_state):
    class Boom(FakeSandboxManager):
        async def create(self, **kw):
            sb = await super().create(**kw)

            async def explode(*a, **k):
                raise RuntimeError("exec exploded")

            sb.exec = explode
            return sb

    mgr = Boom(FILES)
    with override_deps(sandbox_manager=mgr):
        out = await run_sandbox(make_state())
    assert "exec exploded" in out["error"] and mgr.removed == [mgr.only.container_id]


async def test_create_failure_is_an_error(make_state):
    mgr = FakeSandboxManager(FILES)
    mgr.create_error = SandboxError("image not found")
    with override_deps(sandbox_manager=mgr):
        out = await run_sandbox(make_state())
    assert "image not found" in out["error"]


async def test_other_ecosystems_not_supported_yet(make_state):
    out = await run_sandbox(make_state(ecosystem="npm"))
    assert "not implemented yet" in out["error"]
