"""Node 5: create the sandbox, check out the repo and run the baseline install."""

from __future__ import annotations

from typing import Any

import structlog

from src.agent.deps import get_sandbox_manager
from src.agent.nodes import _pip
from src.agent.nodes._common import NodeError, agent_node, make_event
from src.agent.routing import BASELINE_FAILING
from src.agent.state import AgentState
from src.core.config import settings
from src.services.sandbox.base import NetworkDisabledError, tail

log = structlog.get_logger(__name__)


@agent_node("run_sandbox")
async def run_sandbox(state: AgentState) -> dict[str, Any]:
    """Start an ephemeral sandbox and install the repo's *current* dependencies.

    A baseline install failure is a property of the repository, not of our fix, so it ends the
    job as ``BASELINE_FAILING``. The container is removed here if anything after creation fails,
    because its id would otherwise never reach ``cleanup_sandbox``.
    """
    if state.ecosystem != "pip":
        raise NodeError(f"sandbox validation for ecosystem {state.ecosystem!r} is not implemented yet")
    manager = get_sandbox_manager()
    sandbox = await manager.create(job_id=state.job_id, repo_name=state.repo_name, ecosystem=state.ecosystem)
    try:
        result = await _pip.run_install(sandbox, state.manifest_file_path, settings.SANDBOX_TIMEOUT_SECONDS)
    except NetworkDisabledError as exc:
        await manager.remove(sandbox.container_id)
        raise NodeError(str(exc)) from exc
    except BaseException:
        await manager.remove(sandbox.container_id)
        raise

    started = {"container": sandbox.container_id[:12], "ecosystem": state.ecosystem, "network": settings.SANDBOX_NETWORK_MODE}
    events = [*state.audit_events, make_event("SANDBOX_STARTED", started)]
    update: dict[str, Any] = {"sandbox_container_id": sandbox.container_id}
    if not result.ok:
        log.warning("sandbox.baseline_install_failed", exit_code=result.exit_code, timed_out=result.timed_out)
        events.append(make_event("PRE_TESTS_FAILED", {"stage": "baseline install", "output": tail(result.output, 4000)}))
        update["terminal_status"] = BASELINE_FAILING
    update["audit_events"] = events
    return update
