"""Sandbox abstractions used by the agent nodes (Docker in production, fakes in unit tests)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class SandboxError(RuntimeError):
    """Sandbox could not be created or operated (infrastructure problem, not a test failure)."""


class NetworkDisabledError(SandboxError):
    """A step needs registry access but ``SANDBOX_NETWORK_MODE`` is ``none``."""


@dataclass(frozen=True)
class ExecResult:
    """Result of a command run inside the sandbox."""

    exit_code: int
    output: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """True when the command exited 0 within its time limit."""
        return self.exit_code == 0 and not self.timed_out


@runtime_checkable
class Sandbox(Protocol):
    """A running sandbox container with the repository checked out at ``/workspace``."""

    container_id: str

    async def exec(
        self,
        argv: Sequence[str],
        *,
        timeout: int | None = None,
        install: bool = False,
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        """Run ``argv`` (no shell) in the workspace. ``install=True`` marks a step that needs the
        package registry; it raises :class:`NetworkDisabledError` when networking is off."""

    async def read_file(self, path: str) -> str | None:
        """Return a workspace-relative file's text or ``None`` if missing."""

    async def write_file(self, path: str, content: str) -> None:
        """Overwrite a workspace-relative file, keeping its permission bits."""

    async def reset_workspace(self) -> None:
        """Discard all working-tree changes (``git checkout -- . && git clean -fd``)."""


@runtime_checkable
class SandboxManager(Protocol):
    """Creates, re-attaches to, and destroys sandboxes."""

    async def create(self, *, job_id: str, repo_name: str, ecosystem: str) -> Sandbox:
        """Start a sandbox with ``repo_name`` checked out. Respects the global concurrency cap."""

    async def attach(self, container_id: str) -> Sandbox:
        """Re-attach to a sandbox created earlier in the same job."""

    async def remove(self, container_id: str) -> None:
        """Destroy the sandbox; idempotent."""


def tail(text: str, limit: int = 20_000) -> str:
    """Keep the last ``limit`` characters (test/scan output tails carry the useful part)."""
    return text if len(text) <= limit else "...[truncated]...\n" + text[-limit:]


__all__ = ["ExecResult", "NetworkDisabledError", "Sandbox", "SandboxError", "SandboxManager", "tail"]
