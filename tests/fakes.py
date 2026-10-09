"""In-memory sandbox for unit/integration tests (emulates the bits of a pip repo the nodes touch)."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

from src.services.sandbox.base import ExecResult, NetworkDisabledError, SandboxError
from src.utils.version_compare import compare_versions

OK = ExecResult(0, "")
PASSING = "....\n4 passed in 0.12s\n"
_REQ = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;#]+)", re.MULTILINE)


def failing(*names: str, passed: int = 3) -> str:
    """pytest output with the given failing tests."""
    lines = "\n".join(f"FAILED tests/test_app.py::{n} - AssertionError" for n in names)
    return f"{lines}\n{len(names)} failed, {passed} passed in 0.30s\n"


class FakeSandbox:
    """Scriptable sandbox. ``pytest_outputs`` / ``install_results`` are consumed per call (last one repeats)."""

    def __init__(
        self,
        files: dict[str, str],
        *,
        container_id: str = "fake0123456789",
        pytest_outputs: Sequence[str] = (PASSING,),
        install_results: Sequence[ExecResult] = (),
        vulnerable_package: str = "requests",
        fixed_version: str = "2.32.0",
        scan_always_vulnerable: bool = False,
        network_enabled: bool = True,
        scan_error: bool = False,
    ) -> None:
        self.container_id = container_id
        self.files = dict(files)
        self._original = dict(files)
        self.pytest_outputs = list(pytest_outputs)
        self.install_results = list(install_results)
        self.vulnerable_package, self.fixed_version = vulnerable_package, fixed_version
        self.scan_always_vulnerable = scan_always_vulnerable
        self.network_enabled = network_enabled
        self.scan_error = scan_error
        self.venv = False
        self.installed: dict[str, str] = {}
        self.calls: list[list[str]] = []
        self.resets = 0
        self._reports: dict[str, str] = {}

    # -- helpers -----------------------------------------------------------------------------
    @staticmethod
    def _pop(items: list, default: Any) -> Any:
        if not items:
            return default
        return items.pop(0) if len(items) > 1 else items[0]

    def _grype_report(self) -> str:
        ver = self.installed.get(self.vulnerable_package)
        vulnerable = self.scan_always_vulnerable or (ver is not None and compare_versions(ver, self.fixed_version) < 0)
        matches = []
        if vulnerable:
            matches.append({
                "vulnerability": {"id": "GHSA-fake-0000"},
                "relatedVulnerabilities": [{"id": "CVE-2024-35195"}],
                "artifact": {"name": self.vulnerable_package, "version": ver or "?"},
            })  # fmt: skip
        return json.dumps({"matches": matches})

    # -- Sandbox protocol --------------------------------------------------------------------
    async def exec(
        self, argv: Sequence[str], *, timeout: int | None = None, install: bool = False, env: dict[str, str] | None = None
    ) -> ExecResult:
        a = list(argv)
        self.calls.append(a)
        if install and not self.network_enabled:
            raise NetworkDisabledError("network disabled")
        if a[:2] == ["test", "-x"]:
            return OK if self.venv else ExecResult(1, "")
        if a[:3] == ["python", "-m", "venv"]:
            self.venv = True
            return OK
        if a[0].endswith("/pip") and a[1] == "install":
            res = self._pop(self.install_results, OK)
            if res.ok:
                self.installed = {n.lower(): v for n, v in _REQ.findall(self.files.get("requirements.txt", ""))}
            return res
        if a[0].endswith("/pip") and a[1] == "show":
            ver = self.installed.get(a[2].lower())
            return ExecResult(0, f"Name: {a[2]}\nVersion: {ver}\n") if ver else ExecResult(1, "not found")
        if "pytest" in a:
            return ExecResult(0 if "failed" not in (out := self._pop(self.pytest_outputs, PASSING)) else 1, out)
        if a[:2] == ["git", "status"]:
            changed = [p for p, c in self.files.items() if self._original.get(p) != c]
            return ExecResult(0, "".join(f" M {p}\n" for p in changed))
        if a[0] == "grype":
            if self.scan_error:
                return ExecResult(1, "db error")
            self._reports[a[-1].split("=", 1)[1]] = self._grype_report()
            return OK
        if a[0] == "cat" and a[1] in self._reports:
            return ExecResult(0, self._reports[a[1]])
        return OK

    async def read_file(self, path: str) -> str | None:
        return self.files.get(path)

    async def write_file(self, path: str, content: str) -> None:
        self.files[path] = content

    async def reset_workspace(self) -> None:
        self.resets += 1
        self.files = dict(self._original)


class FakeSandboxManager:
    """Hands out one :class:`FakeSandbox` per ``create`` and tracks lifecycle."""

    def __init__(self, files: dict[str, str] | None = None, **sandbox_kwargs: Any) -> None:
        self._files = files or {}
        self._kwargs = sandbox_kwargs
        self.sandboxes: dict[str, FakeSandbox] = {}
        self.removed: list[str] = []
        self.create_error: Exception | None = None

    async def create(self, *, job_id: str, repo_name: str, ecosystem: str) -> FakeSandbox:
        if self.create_error:
            raise self.create_error
        sb = FakeSandbox(self._files, container_id=f"fake{len(self.sandboxes):010d}", **self._kwargs)
        self.sandboxes[sb.container_id] = sb
        return sb

    async def attach(self, container_id: str) -> FakeSandbox:
        if container_id not in self.sandboxes or container_id in self.removed:
            raise SandboxError("sandbox no longer exists")
        return self.sandboxes[container_id]

    async def remove(self, container_id: str) -> None:
        self.removed.append(container_id)

    @property
    def only(self) -> FakeSandbox:
        (sb,) = self.sandboxes.values()
        return sb


# ------------------------------------------------------------------ PR / idempotency / audit / notifications
from src.services.github.pr_creator import ExistingPR, PRResult  # noqa: E402
from src.services.notifications.base import NotificationHandler  # noqa: E402


class FakePRService:
    """Records PR creation; configurable existing PR, owners and failures."""

    def __init__(self, owners=("@alice", "@org/platform"), existing: ExistingPR | None = None, create_error: Exception | None = None,
                 protection: dict | None = None, warnings: list[str] | None = None) -> None:  # fmt: skip
        self.owners = list(owners)
        self.existing = existing
        self.create_error = create_error
        self.protection = protection if protection is not None else {"protected": True, "code_owner_reviews_required": True}
        self.warnings = warnings or []
        self.created: list[dict] = []
        self.find_calls = 0

    async def find_open_pr(self, repo, cve_id, branch_prefix):
        self.find_calls += 1
        return self.existing

    async def get_code_owners(self, repo, paths):
        self.paths = paths
        return list(self.owners)

    async def branch_protection(self, repo):
        return self.protection

    async def create_pr(self, **kw):
        if self.create_error:
            raise self.create_error
        self.created.append(kw)
        n = 100 + len(self.created)
        return PRResult(f"https://github.com/{kw['repo']}/pull/{n}", n, kw["branch"], "main", list(kw["labels"]),
                        [f"@{u}" for u in kw["users"]] + [f"@{t}" for t in kw["teams"]], list(self.warnings))  # fmt: skip


class MemoryIdempotency:
    """In-memory :class:`IdempotencyStore`."""

    def __init__(self) -> None:
        self.data: dict[str, dict] = {}

    async def get(self, key):
        return self.data.get(key)

    async def put(self, key, scope, result):
        self.data.setdefault(key, result)


class MemoryAuditStore:
    """In-memory :class:`AuditStore` with the same once-per-job semantics as the DB one."""

    def __init__(self) -> None:
        self.flushed: dict[str, tuple] = {}
        self.attempts = 0
        self.fail_times = 0

    async def flush(self, summary, events):
        self.attempts += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("database unavailable")
        if summary.job_id in self.flushed:
            return False
        self.flushed[summary.job_id] = (summary, list(events))
        return True


class MemoryNotificationLog:
    """In-memory :class:`NotificationLogStore`."""

    def __init__(self) -> None:
        self.rows: list[tuple] = []

    async def record(self, notification, result, idempotency_key):
        self.rows.append((result.channel, result.status, idempotency_key))


class RecordingHandler(NotificationHandler):
    """Channel that records what it was asked to send (or fails on demand)."""

    def __init__(self, name="teams", fail_times=0, supported=True, needs_recipients=False):
        self.name, self.fail_times, self._supported, self._needs = name, fail_times, supported, needs_recipients
        self.sent: list = []
        self.attempts = 0

    def supports(self, n):
        return self._supported and (bool(n.recipients) if self._needs else True)

    async def send(self, n):
        self.attempts += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise ConnectionError("channel down")
        self.sent.append(n)
        return {"ok": True}
