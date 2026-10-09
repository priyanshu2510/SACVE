"""Docker-backed sandbox.

Isolation (locked design): non-root user, ``cap_drop=ALL``, ``no-new-privileges``, read-only root
filesystem with size-limited tmpfs mounts for the workspace / venv / tmp, no Docker socket, no host
bind mounts, memory + CPU + pids limits, and no network (``none``) unless an *internal* egress network
fronted by a registry allowlist proxy is configured (``SANDBOX_NETWORK_MODE=registry-allowlist``).
The repository is cloned on the host and copied in, so the token never enters the sandbox.
"""

from __future__ import annotations

import asyncio
import io
import socket
import tarfile
import tempfile
import threading
import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any, Protocol

import docker
import structlog
from docker.errors import APIError, ImageNotFound, NotFound

from src.core.config import Settings, settings as default_settings
from src.services.sandbox.base import ExecResult, NetworkDisabledError, SandboxError
from src.services.sandbox.git_clone import clone_repo

log = structlog.get_logger(__name__)

WORKSPACE = "/workspace"
SANDBOX_UID = 1000
LABEL = "cve-remediation.sandbox"
LABEL_JOB = "cve-remediation.job_id"
MAX_OUTPUT_CHARS = 200_000
CloneFn = Callable[[str, Path], Awaitable[str]]


class SlotLimiter(Protocol):
    """Caps concurrent sandboxes. ``holder`` identifies one lease."""

    async def acquire(self, holder: str) -> None:
        """Wait for a free slot."""

    async def release(self, holder: str) -> None:
        """Free the slot (idempotent)."""


class LocalSlotLimiter:
    """Per-process cap (threading semaphore, so it survives the fresh event loop of each Celery task)."""

    def __init__(self, limit: int) -> None:
        self._sem = threading.BoundedSemaphore(limit)
        self._held: set[str] = set()

    async def acquire(self, holder: str) -> None:
        """Block (in a worker thread) until a slot is free."""
        await asyncio.to_thread(self._sem.acquire)
        self._held.add(holder)

    async def release(self, holder: str) -> None:
        """Free the slot if ``holder`` has one."""
        if holder in self._held:
            self._held.discard(holder)
            self._sem.release()


class RedisSlotLimiter:
    """Cluster-wide cap shared by every worker (leases expire, so a crashed worker cannot leak slots)."""

    def __init__(self, semaphore: Any) -> None:
        self._sem = semaphore

    async def acquire(self, holder: str) -> None:
        """Wait for a slot in Redis."""
        await self._sem.acquire(holder)

    async def release(self, holder: str) -> None:
        """Release the Redis lease."""
        await self._sem.release(holder)

_IMAGES = {"pip": "SANDBOX_IMAGE_PYTHON"}  # other ecosystems get images in later milestones


def _tar_of(path: Path) -> bytes:
    """Tar a directory tree (contents at the archive root), owned by the sandbox user."""

    def own(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = info.gid = SANDBOX_UID
        info.uname = info.gname = ""
        return info

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(path, arcname=".", filter=own)
    return buf.getvalue()


def _tar_of_file(name: str, data: bytes, mode: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.uid, info.gid = len(data), mode, SANDBOX_UID, SANDBOX_UID
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _put_tar(container: Any, directory: str, data: bytes) -> None:
    """Extract a tar archive into ``directory`` by streaming it to ``tar -x`` over exec stdin.

    ``Container.put_archive`` is refused by Docker for read-only root filesystems, so the archive is
    piped through an exec instead. Raises :class:`SandboxError` if extraction fails.
    """
    api = container.client.api
    exec_id = api.exec_create(
        container.id, ["tar", "-x", "-C", directory], stdin=True, stdout=True, stderr=True, user=str(SANDBOX_UID)
    )["Id"]
    sock = api.exec_start(exec_id, socket=True)
    raw = sock._sock  # docker-py wraps the connection; the raw socket is needed to half-close
    try:
        raw.sendall(data)
        raw.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := raw.recv(65536):
            chunks.append(chunk)
    finally:
        sock.close()
    code = api.exec_inspect(exec_id).get("ExitCode")
    if code != 0:
        detail = b"".join(chunks).decode("utf-8", errors="replace")[-300:]
        raise SandboxError(f"extracting archive into {directory} failed (exit {code}): {detail}")


def _workspace_path(path: str) -> tuple[str, str]:
    """Return ``(directory, filename)`` inside the workspace, rejecting traversal."""
    clean = Path(path)
    if clean.is_absolute() or ".." in clean.parts:
        raise SandboxError(f"path escapes the workspace: {path}")
    full = Path(WORKSPACE) / clean
    return str(full.parent), full.name


class DockerSandbox:
    """A running sandbox container."""

    def __init__(self, container: Any, cfg: Settings) -> None:
        self._c = container
        self._cfg = cfg
        self.container_id: str = container.id

    async def exec(
        self,
        argv: Sequence[str],
        *,
        timeout: int | None = None,
        install: bool = False,
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        """Run ``argv`` inside the container under ``timeout(1)``; exit code 124 means timed out."""
        limit = timeout or self._cfg.SANDBOX_TIMEOUT_SECONDS
        environment = dict(env or {})
        if install:
            if self._cfg.SANDBOX_NETWORK_MODE != "registry-allowlist":
                raise NetworkDisabledError(
                    "this step needs the package registry but SANDBOX_NETWORK_MODE=none; "
                    "set SANDBOX_NETWORK_MODE=registry-allowlist and provision the egress network"
                )
            if self._cfg.SANDBOX_PROXY_URL:
                environment.update(HTTP_PROXY=self._cfg.SANDBOX_PROXY_URL, HTTPS_PROXY=self._cfg.SANDBOX_PROXY_URL)
            if self._cfg.SANDBOX_PIP_INDEX_URL:
                environment["PIP_INDEX_URL"] = self._cfg.SANDBOX_PIP_INDEX_URL
        cmd = ["timeout", "-k", "5", str(limit), *argv]

        def _run() -> tuple[int, bytes]:
            code, out = self._c.exec_run(cmd, workdir=WORKSPACE, environment=environment, user=str(SANDBOX_UID))
            return code, out or b""

        try:
            code, raw = await asyncio.wait_for(asyncio.to_thread(_run), timeout=limit + 30)
        except asyncio.TimeoutError:
            return ExecResult(124, "sandbox exec watchdog expired", timed_out=True)
        except APIError as exc:
            raise SandboxError(f"docker exec failed: {exc}") from exc
        text = raw.decode("utf-8", errors="replace")
        if len(text) > MAX_OUTPUT_CHARS:
            text = "...[truncated]...\n" + text[-MAX_OUTPUT_CHARS:]
        return ExecResult(code, text, timed_out=code in (124, 137))

    async def read_file(self, path: str) -> str | None:
        """Read a workspace file via ``cat`` (None if absent)."""
        directory, name = _workspace_path(path)
        res = await self.exec(["cat", f"{directory}/{name}"], timeout=30)
        return res.output if res.ok else None

    async def write_file(self, path: str, content: str) -> None:
        """Replace a workspace file's content (tar upload; no shell quoting involved)."""
        directory, name = _workspace_path(path)
        mode_res = await self.exec(["stat", "-c", "%a", f"{directory}/{name}"], timeout=30)
        mode = int(mode_res.output.strip(), 8) if mode_res.ok and mode_res.output.strip().isdigit() else 0o644
        archive = _tar_of_file(name, content.encode(), mode)
        await asyncio.to_thread(_put_tar, self._c, directory, archive)

    async def reset_workspace(self) -> None:
        """Discard working-tree changes so a repair attempt starts from a clean checkout."""
        for argv in (["git", "checkout", "--", "."], ["git", "clean", "-fdq"]):
            res = await self.exec(argv, timeout=120)
            if not res.ok:
                raise SandboxError(f"workspace reset failed ({' '.join(argv)}): {res.output[-300:]}")


class DockerSandboxManager:
    """Creates hardened sandboxes under a process-wide concurrency cap."""

    def __init__(
        self,
        cfg: Settings | None = None,
        *,
        client: docker.DockerClient | None = None,
        clone: CloneFn | None = None,
        slots: SlotLimiter | None = None,
    ) -> None:
        self._cfg = cfg or default_settings
        self._client = client or docker.from_env()
        self._clone = clone or (lambda repo, dest: clone_repo(repo, dest, self._cfg))
        self._slots: SlotLimiter = slots or LocalSlotLimiter(self._cfg.MAX_CONCURRENT_SANDBOXES)
        self._holders: dict[str, str] = {}  # container id -> lease holder

    # -- network -----------------------------------------------------------------------------

    def _network_mode(self) -> str:
        if self._cfg.SANDBOX_NETWORK_MODE == "none":
            return "none"
        name = self._cfg.SANDBOX_EGRESS_NETWORK
        try:
            net = self._client.networks.get(name)
        except NotFound as exc:
            raise SandboxError(f"egress network {name!r} does not exist") from exc
        if not net.attrs.get("Internal") and not self._cfg.SANDBOX_ALLOW_NON_INTERNAL_NETWORK:
            raise SandboxError(
                f"egress network {name!r} is not internal; refusing to run sandboxes with open internet access"
            )
        return name

    # -- lifecycle ---------------------------------------------------------------------------

    def _remove_stale(self, job_id: str) -> None:
        for c in self._client.containers.list(all=True, filters={"label": f"{LABEL_JOB}={job_id}"}):
            log.warning("sandbox.remove_stale", container=c.short_id, job_id=job_id)
            c.remove(force=True)

    def _create_container(self, job_id: str, ecosystem: str) -> Any:
        image_key = _IMAGES.get(ecosystem)
        if image_key is None:
            raise SandboxError(f"no sandbox image for ecosystem {ecosystem!r} yet")
        image = getattr(self._cfg, image_key)
        cfg = self._cfg
        tmpfs_base = f"rw,exec,nosuid,uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0755"
        try:
            container = self._client.containers.create(
                image,
                command=["sleep", "infinity"],
                name=f"cve-sandbox-{job_id[:12]}-{uuid.uuid4().hex[:6]}",
                labels={LABEL: "1", LABEL_JOB: job_id},
                user=str(SANDBOX_UID),
                working_dir=WORKSPACE,
                read_only=True,
                tmpfs={
                    WORKSPACE: f"{tmpfs_base},size={cfg.SANDBOX_WORKSPACE_TMPFS}",
                    "/opt/venv": f"{tmpfs_base},size={cfg.SANDBOX_VENV_TMPFS}",
                    "/tmp": f"rw,exec,nosuid,uid={SANDBOX_UID},gid={SANDBOX_UID},mode=1777,size=128m",
                },
                network_mode=self._network_mode(),
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                mem_limit=cfg.SANDBOX_MEM_LIMIT,
                memswap_limit=cfg.SANDBOX_MEM_LIMIT,  # no swap
                cpu_period=100_000,
                cpu_quota=cfg.SANDBOX_CPU_QUOTA,
                pids_limit=cfg.SANDBOX_PIDS_LIMIT,
                init=True,
                environment={"HOME": "/tmp"},
            )
        except ImageNotFound as exc:
            raise SandboxError(f"sandbox image {image!r} not found; build it from docker/sandbox/") from exc
        container.start()
        return container

    async def create(self, *, job_id: str, repo_name: str, ecosystem: str) -> DockerSandbox:
        """Acquire a slot, start the container, clone the repo on the host and copy it in."""
        holder = f"{job_id}:{uuid.uuid4().hex[:8]}"
        await self._slots.acquire(holder)
        container = None
        try:
            await asyncio.to_thread(self._remove_stale, job_id)
            container = await asyncio.to_thread(self._create_container, job_id, ecosystem)
            with tempfile.TemporaryDirectory(prefix="cve-clone-") as tmp:
                dest = Path(tmp) / "repo"
                sha = await self._clone(repo_name, dest)
                archive = await asyncio.to_thread(_tar_of, dest)
            await asyncio.to_thread(_put_tar, container, WORKSPACE, archive)
            self._holders[container.id] = holder
            log.info("sandbox.started", container=container.short_id, repo=repo_name, commit=sha)
            return DockerSandbox(container, self._cfg)
        except BaseException:
            if container is not None:
                await asyncio.to_thread(self._force_remove, container)
            await self._slots.release(holder)
            raise

    async def attach(self, container_id: str) -> DockerSandbox:
        """Re-attach to a running sandbox by id."""
        try:
            container = await asyncio.to_thread(self._client.containers.get, container_id)
        except NotFound as exc:
            raise SandboxError(f"sandbox {container_id[:12]} no longer exists") from exc
        return DockerSandbox(container, self._cfg)

    @staticmethod
    def _force_remove(container: Any) -> None:
        try:
            container.remove(force=True)
        except NotFound:
            pass

    async def remove(self, container_id: str) -> None:
        """Force-remove the container (idempotent) and free its concurrency slot."""
        try:
            container = await asyncio.to_thread(self._client.containers.get, container_id)
            await asyncio.to_thread(self._force_remove, container)
        except NotFound:
            pass
        holder = self._holders.pop(container_id, None)
        if holder is not None:
            await self._slots.release(holder)
        log.info("sandbox.removed", container=container_id[:12])
