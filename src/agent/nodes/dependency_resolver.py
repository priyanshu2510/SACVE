"""Node: resolve dependencies in the sandbox after the patch so bumps resolve transitively."""

from __future__ import annotations

from typing import Any

from src.agent.deps import get_sandbox_manager
from src.agent.nodes import _pip
from src.agent.nodes._common import NodeError, agent_node, make_event, record_failure
from src.agent.state import AgentState
from src.core.config import settings
from src.services.sandbox.base import NetworkDisabledError, tail
from src.utils.packages import normalise_pip_name
from src.utils.version_compare import compare_versions


async def _installed_version(sandbox: Any, package: str) -> str | None:
    res = await sandbox.exec([_pip.PIP, "show", normalise_pip_name(package)], timeout=60)
    if not res.ok:
        return None
    for line in res.output.splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
    return None


@agent_node("resolve_dependencies")
async def resolve_dependencies(state: AgentState) -> dict[str, Any]:
    """Install the patched manifest and verify the vulnerable package really resolved to the target.

    Failures (resolver conflict, install error, package left below ``target_version``) are
    repairable: they feed the repair loop. A disabled network is a configuration error instead.
    """
    if not state.sandbox_container_id:
        raise NodeError("resolve_dependencies requires a sandbox")
    sandbox = await get_sandbox_manager().attach(state.sandbox_container_id)
    try:
        res = await _pip.run_install(sandbox, state.manifest_file_path, settings.SANDBOX_TIMEOUT_SECONDS)
    except NetworkDisabledError as exc:
        raise NodeError(str(exc)) from exc
    output = tail(res.output, 6000)
    if not res.ok:
        why = "timed out" if res.timed_out else f"failed (exit {res.exit_code})"
        return record_failure(state, f"dependency installation {why}:\n{tail(res.output, 3000)}") | {
            "dependency_resolution_output": output
        }

    installed = await _installed_version(sandbox, state.affected_package)
    if installed is None or compare_versions(installed, state.target_version) < 0:
        return record_failure(
            state,
            f"after installing, {state.affected_package} resolved to {installed or 'nothing'}, "
            f"below the required {state.target_version} (conflicting constraints or an unpinned manifest?)",
        ) | {"dependency_resolution_output": output}

    status = await sandbox.exec(["git", "status", "--porcelain"], timeout=60)
    changed = [line[3:].strip() for line in status.output.splitlines() if line.strip()] if status.ok else []
    return {
        "dependency_resolution_output": output,
        "lockfile_changes": changed,
        "audit_events": [
            *state.audit_events,
            make_event("PATCH_APPLIED", {"stage": "dependencies resolved", "package": state.affected_package,
                                         "resolved_version": installed, "changed_files": changed}),
        ],  # fmt: skip
    }
