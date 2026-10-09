"""Real Docker: hardening, file ops, limits, and the pip pipeline end to end.

Needs a running Docker daemon and the ``cve-sandbox-python`` image (docker/sandbox/python.Dockerfile).
The full-pipeline tests also need internet (PyPI) and run the sandbox on the default bridge network,
which is only allowed here through ``SANDBOX_ALLOW_NON_INTERNAL_NETWORK``.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

import docker
import httpx
import pytest
from docker.errors import DockerException
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import SecretStr

from src.agent.deps import override_deps
from src.agent.nodes import _pip
from src.agent.nodes.security_scanner import run_security_scan
from src.agent.runner import run_fix_agent
from src.core.config import Settings
from src.services.sandbox.base import SandboxError
from src.services.sandbox.docker_sandbox import LABEL, DockerSandboxManager
from tests.conftest import FakeContentSource
from tests.integration.test_graph_core_run import INITIAL
from tests.llm_helpers import Recorder, chat, good

pytestmark = pytest.mark.docker
IMAGE = "cve-sandbox-python:latest"

REQS = "requests==2.31.0\n"
TEST_FILE = "import requests\n\n\ndef test_requests_importable():\n    assert requests.__version__\n"
APP = "import requests\n\n\ndef get(url):\n    return requests.get(url)\n"


def _docker_client():
    try:
        client = docker.from_env()
        client.ping()
        client.images.get(IMAGE)
        return client
    except (DockerException, Exception):  # noqa: BLE001
        return None


@pytest.fixture(scope="module")
def client():
    c = _docker_client()
    if c is None:
        pytest.skip(f"Docker daemon or image {IMAGE} not available")
    return c


@pytest.fixture
def repo(tmp_path) -> Path:
    """A tiny pip project with one passing test, as a git repo."""
    root = tmp_path / "origin"
    (root / "tests").mkdir(parents=True)
    (root / "app").mkdir()
    (root / "requirements.txt").write_text(REQS)
    (root / "tests" / "test_app.py").write_text(TEST_FILE)
    (root / "app" / "client.py").write_text(APP)
    (root / "run.sh").write_text("#!/bin/sh\necho hi\n")
    (root / "run.sh").chmod(0o755)
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin"}
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "init"]):
        subprocess.run(["git", "-C", str(root), *cmd], check=True, env=env)
    return root


def make_manager(client, repo: Path, **cfg) -> DockerSandboxManager:
    async def clone(repo_name: str, dest: Path) -> str:
        shutil.copytree(repo, dest)
        return "local"

    settings = Settings(_env_file=None, SANDBOX_IMAGE_PYTHON=IMAGE, **cfg)
    return DockerSandboxManager(settings, client=client, clone=clone)


@pytest.fixture
async def sandbox(client, repo):
    mgr = make_manager(client, repo)
    sb = await mgr.create(job_id="it-hardening", repo_name="o/r", ecosystem="pip")
    try:
        yield mgr, sb
    finally:
        await mgr.remove(sb.container_id)


# ---------------------------------------------------------------- hardening


async def test_container_is_hardened(client, sandbox):
    _, sb = sandbox
    host = client.api.inspect_container(sb.container_id)["HostConfig"]
    cfg = client.api.inspect_container(sb.container_id)["Config"]
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"] and "no-new-privileges" in host["SecurityOpt"][0]
    assert host["NetworkMode"] == "none"
    assert host["Memory"] == 2 * 1024**3 and host["MemorySwap"] == host["Memory"]
    assert host["CpuQuota"] == 50000 and host["PidsLimit"] == 256
    assert not host.get("Binds") and not host.get("Privileged")
    assert cfg["User"] == "1000" and cfg["Labels"][LABEL] == "1"
    assert {"/workspace", "/opt/venv", "/tmp"} <= set(host["Tmpfs"])


async def test_runtime_isolation(sandbox):
    _, sb = sandbox
    assert (await sb.exec(["id", "-u"])).output.strip() == "1000"
    assert not (await sb.exec(["touch", "/etc/pwned"])).ok  # read-only root filesystem
    assert (await sb.exec(["touch", "/workspace/ok"])).ok  # writable tmpfs workspace
    sock = "import socket; socket.create_connection(('1.1.1.1', 80), timeout=3)"
    assert not (await sb.exec(["python", "-c", sock])).ok  # no network
    assert not (await sb.exec(["ls", "/var/run/docker.sock"])).ok  # no docker socket
    assert "CapEff:\t0000000000000000" in (await sb.exec(["grep", "CapEff", "/proc/self/status"])).output


async def test_no_registry_access_without_allowlist_mode(sandbox):
    from src.services.sandbox.base import NetworkDisabledError

    _, sb = sandbox
    with pytest.raises(NetworkDisabledError):
        await sb.exec(["true"], install=True)


# ---------------------------------------------------------------- files, reset, timeout


async def test_repo_is_checked_out_and_owned_by_sandbox_user(sandbox):
    _, sb = sandbox
    assert await sb.read_file("requirements.txt") == REQS
    assert (await sb.exec(["git", "rev-parse", "--is-inside-work-tree"])).output.strip() == "true"
    assert (await sb.exec(["stat", "-c", "%u", "requirements.txt"])).output.strip() == "1000"
    assert await sb.read_file("does/not/exist") is None


async def test_write_read_reset_roundtrip_keeps_modes(sandbox):
    _, sb = sandbox
    await sb.write_file("requirements.txt", "requests==2.32.0\n")
    await sb.write_file("run.sh", "#!/bin/sh\necho patched\n")
    assert await sb.read_file("requirements.txt") == "requests==2.32.0\n"
    assert (await sb.exec(["stat", "-c", "%a", "run.sh"])).output.strip() == "755"  # exec bit preserved
    await sb.exec(["touch", "untracked.txt"])
    status = (await sb.exec(["git", "status", "--porcelain"])).output
    assert "requirements.txt" in status and "untracked.txt" in status
    await sb.reset_workspace()
    assert await sb.read_file("requirements.txt") == REQS
    assert (await sb.exec(["git", "status", "--porcelain"])).output.strip() == ""


async def test_path_traversal_is_rejected(sandbox):
    _, sb = sandbox
    with pytest.raises(SandboxError):
        await sb.write_file("../etc/passwd", "x")
    with pytest.raises(SandboxError):
        await sb.read_file("/etc/passwd")


async def test_exec_timeout(sandbox):
    _, sb = sandbox
    res = await sb.exec(["sleep", "30"], timeout=2)
    assert res.timed_out and not res.ok


# ---------------------------------------------------------------- lifecycle & concurrency


async def test_remove_is_idempotent_and_frees_the_slot(client, repo):
    mgr = make_manager(client, repo, MAX_CONCURRENT_SANDBOXES=1)
    first = await mgr.create(job_id="it-cap-1", repo_name="o/r", ecosystem="pip")
    second = asyncio.create_task(mgr.create(job_id="it-cap-2", repo_name="o/r", ecosystem="pip"))
    await asyncio.sleep(1.5)
    assert not second.done()  # cap of 1: the second sandbox waits for a slot
    await mgr.remove(first.container_id)
    await mgr.remove(first.container_id)  # idempotent
    sb2 = await asyncio.wait_for(second, 60)
    await mgr.remove(sb2.container_id)
    assert client.containers.list(all=True, filters={"label": f"{LABEL}=1", "name": "cve-sandbox-it-cap"}) == []


async def test_stale_container_for_same_job_is_reclaimed(client, repo):
    mgr = make_manager(client, repo)
    old = await mgr.create(job_id="it-stale", repo_name="o/r", ecosystem="pip")  # simulates a crashed run
    new = await mgr.create(job_id="it-stale", repo_name="o/r", ecosystem="pip")
    ids = [c.id for c in client.containers.list(all=True, filters={"label": "cve-remediation.job_id=it-stale"})]
    await mgr.remove(new.container_id)
    assert ids == [new.container_id] and old.container_id not in ids


async def test_failed_clone_leaves_no_container_behind(client):
    async def bad_clone(repo_name, dest):
        raise SandboxError("git clone failed")

    mgr = DockerSandboxManager(Settings(_env_file=None, SANDBOX_IMAGE_PYTHON=IMAGE), client=client, clone=bad_clone)
    with pytest.raises(SandboxError):
        await mgr.create(job_id="it-badclone", repo_name="o/r", ecosystem="pip")
    assert client.containers.list(all=True, filters={"label": "cve-remediation.job_id=it-badclone"}) == []
    # the slot was released, so a later create can still proceed
    assert mgr._slots._sem.acquire(blocking=False)
    mgr._slots._sem.release()


async def test_missing_image_is_a_clear_error(client, repo):
    mgr = make_manager(client, repo)
    mgr._cfg = Settings(_env_file=None, SANDBOX_IMAGE_PYTHON="cve-sandbox-does-not-exist:0")
    with pytest.raises(SandboxError, match="not found"):
        await mgr.create(job_id="it-noimage", repo_name="o/r", ecosystem="pip")


async def test_registry_mode_refuses_a_non_internal_network(client, repo):
    mgr = make_manager(client, repo, SANDBOX_NETWORK_MODE="registry-allowlist", SANDBOX_EGRESS_NETWORK="bridge")
    with pytest.raises(SandboxError, match="not internal"):
        await mgr.create(job_id="it-open-net", repo_name="o/r", ecosystem="pip")


# ---------------------------------------------------------------- full pip pipeline (needs PyPI)


@pytest.fixture
def online_manager(client, repo):
    return make_manager(
        client, repo, SANDBOX_NETWORK_MODE="registry-allowlist", SANDBOX_EGRESS_NETWORK="bridge",
        SANDBOX_ALLOW_NON_INTERNAL_NETWORK=True,
    )  # fmt: skip


def _skip_without_pypi():
    try:
        httpx.get("https://pypi.org/simple/requests/", timeout=5).raise_for_status()
    except httpx.HTTPError:
        pytest.skip("PyPI not reachable")


async def test_scanner_detects_the_vulnerable_version_before_the_fix(online_manager, make_state):
    _skip_without_pypi()
    sb = await online_manager.create(job_id="it-scan", repo_name="o/r", ecosystem="pip")
    try:
        res = await _pip.run_install(sb, "requirements.txt", 600)
        assert res.ok, res.output[-500:]
        with override_deps(sandbox_manager=online_manager):
            out = await run_security_scan(make_state(sandbox_container_id=sb.container_id, fix_attempt=1))
        assert out["scanner_cve_resolved"] is False
        assert "CVE-2024-35195" in out["failure_reason"] and "requests 2.31.0" in out["failure_reason"]
    finally:
        await online_manager.remove(sb.container_id)


async def test_full_graph_against_real_docker_and_pypi(online_manager, monkeypatch, agent_deps):
    """Real clone copy, venv, pip install, pytest and grype; only the LLM and GitHub reads are faked."""
    _skip_without_pypi()
    monkeypatch.setattr("src.agent.nodes.fix_generator.default_settings.LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr("src.agent.runner.settings.AUTOMATION_ENABLED", True)
    monkeypatch.setattr("src.agent.nodes.sandbox_executor.settings.SANDBOX_NETWORK_MODE", "registry-allowlist")
    monkeypatch.setattr("src.agent.nodes.sandbox_executor.settings.SANDBOX_TIMEOUT_SECONDS", 600)
    src = FakeContentSource(
        files={"requirements.txt": REQS, "app/client.py": APP}, search={"requests": ["app/client.py"]}, release_notes="## 2.32.0"
    )
    rec = Recorder(chat(good()))  # requests==2.31.0 -> 2.32.0
    with agent_deps(src, llm_transport=httpx.MockTransport(rec), sandbox=online_manager):
        final = await run_fix_agent("it-e2e", INITIAL | {"job_id": "it-e2e"}, checkpointer=InMemorySaver())

    assert final.error is None, final.error
    assert final.terminal_status == "PR_RAISED", (final.terminal_status, final.failure_reason)
    assert final.pre_fix_tests.passed == 1 and final.post_fix_tests.passed == 1
    assert final.scanner_cve_resolved is True and final.test_delta_passed is True
    assert final.confidence_score == 90 and final.sandbox_container_id is None
    assert "requests==2.32.0" in final.dependency_resolution_output or "2.32.0" in final.dependency_resolution_output


@pytest.mark.redis
async def test_redis_slot_cap_is_shared_by_separate_workers(client, repo):
    """Two managers (= two worker processes) share one cap through Redis."""
    import redis.asyncio as aioredis

    from src.core.config import settings as app_settings
    from src.services.sandbox.docker_sandbox import RedisSlotLimiter
    from src.utils.redis_locks import RedisSemaphore

    url = app_settings.REDIS_URL.rsplit("/", 1)[0] + "/13"
    r = aioredis.from_url(url)
    try:
        await r.ping()
    except Exception:
        pytest.skip("Redis not reachable")
    await r.delete("it-slots")

    def worker() -> DockerSandboxManager:
        limiter = RedisSlotLimiter(RedisSemaphore(aioredis.from_url(url), "it-slots", 1, 120))
        mgr = make_manager(client, repo)
        mgr._slots = limiter
        return mgr

    w1, w2 = worker(), worker()
    first = await w1.create(job_id="it-redis-1", repo_name="o/r", ecosystem="pip")
    second = asyncio.create_task(w2.create(job_id="it-redis-2", repo_name="o/r", ecosystem="pip"))
    await asyncio.sleep(2.5)
    assert not second.done()  # the other worker holds the only slot
    await w1.remove(first.container_id)
    sb2 = await asyncio.wait_for(second, 60)
    await w2.remove(sb2.container_id)
    assert await r.zcard("it-slots") == 0  # both leases returned
    await r.delete("it-slots")
    await r.aclose()
