"""pip-specific sandbox helpers shared by the baseline install and ``resolve_dependencies``."""

from __future__ import annotations

import posixpath

from src.agent.nodes._common import NodeError
from src.services.sandbox.base import ExecResult, Sandbox

VENV = "/opt/venv"
PIP = f"{VENV}/bin/pip"
PYTHON = f"{VENV}/bin/python"

_DEV_REQUIREMENT_FILES = (
    "requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt",
    "requirements-test.txt", "requirements_test.txt", "test-requirements.txt",
)  # fmt: skip
_PROJECT_MANIFESTS = {"pyproject.toml", "setup.py", "setup.cfg"}


def is_requirements_file(path: str) -> bool:
    """``requirements*.txt`` / ``constraints*.txt`` style manifest."""
    name = posixpath.basename(path).lower()
    return name.endswith(".txt") and name.startswith(("requirements", "constraints"))


async def install_args(sandbox: Sandbox, manifest_path: str) -> list[str]:
    """Build the ``pip install`` argv for the repo's manifest (plus dev requirement files and pytest)."""
    name = posixpath.basename(manifest_path).lower()
    if is_requirements_file(manifest_path):
        args = [PIP, "install", "-r", manifest_path]
    elif name in _PROJECT_MANIFESTS:
        args = [PIP, "install", "."]
    else:
        raise NodeError(f"unsupported pip manifest for sandbox installs: {manifest_path}")
    root = posixpath.dirname(manifest_path)
    for dev in _DEV_REQUIREMENT_FILES:
        candidate = posixpath.join(root, dev)
        if candidate != manifest_path and await sandbox.read_file(candidate) is not None:
            args += ["-r", candidate]
    return [*args, "pytest"]


async def ensure_venv(sandbox: Sandbox) -> None:
    """Create ``/opt/venv`` if it does not exist yet."""
    if (await sandbox.exec(["test", "-x", PYTHON], timeout=30)).ok:
        return
    res = await sandbox.exec(["python", "-m", "venv", VENV], timeout=120)
    if not res.ok:
        raise NodeError(f"could not create virtualenv: {res.output[-300:]}")


async def run_install(sandbox: Sandbox, manifest_path: str, timeout: int) -> ExecResult:
    """Create the venv if needed and install the project's dependencies (needs registry access)."""
    await ensure_venv(sandbox)
    return await sandbox.exec(await install_args(sandbox, manifest_path), timeout=timeout, install=True)
