"""Run the fix-agent graph for one job, checkpointed to PostgreSQL (``thread_id = job_id``)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from src.agent.graph import RECURSION_LIMIT, build_fix_agent_graph
from src.agent.nodes._common import make_event
from src.agent.state import AgentState
from src.core.config import settings
from src.core.logging import bind_job

log = structlog.get_logger(__name__)


PAUSED = "PAUSED"
# Nodes that only make sense inside a live sandbox: pausing before one of them rewinds to sandbox creation.
SANDBOX_PHASE = {"run_pre_tests", "apply_patch", "resolve_dependencies", "run_post_tests", "run_security_scan"}
PauseCheck = Callable[[], Awaitable[bool]]


async def _drive(graph: Any, graph_input: Any, config: dict[str, Any], should_pause: PauseCheck | None) -> bool:
    """Run the graph superstep by superstep; returns ``True`` if it stopped early because a pause was requested."""
    stream = graph.astream(graph_input, config=config, stream_mode="values")
    try:
        async for _ in stream:
            if should_pause is not None and await should_pause():
                return True
    finally:
        await stream.aclose()
    return False


async def _park(graph: Any, config: dict[str, Any]) -> AgentState:
    """Leave a paused run in a resumable state: drop its sandbox and make sure resume does not need it.

    State patches are attributed to a node whose outgoing edge leads to the *same* next step, so
    pausing never changes what runs next -- except when the next step needs a live sandbox, in which
    case the run is rewound to sandbox creation.
    """
    from src.agent.deps import get_sandbox_manager

    snapshot = await graph.aget_state(config)
    container = (snapshot.values or {}).get("sandbox_container_id")
    next_nodes = set(snapshot.next)
    if container:
        try:
            await get_sandbox_manager().remove(container)
        except Exception as exc:  # noqa: BLE001 - the label sweep reclaims a leaked container on the next create
            log.error("agent.pause_cleanup_failed", error=str(exc))
        if next_nodes & SANDBOX_PHASE:
            # re-enter through scoring: with no sandbox, route_after_scoring sends the run to run_sandbox
            patch = {"sandbox_container_id": None, "failure_reason": None, "terminal_status": None}
            await graph.aupdate_state(config, patch, as_node="score_confidence")
        elif next_nodes == {"generate_fix"}:  # retry pending: any retry-producing router leads to generate_fix
            await graph.aupdate_state(config, {"sandbox_container_id": None}, as_node="run_post_tests")
        elif next_nodes == {"score_confidence"}:  # new attempt just generated
            await graph.aupdate_state(config, {"sandbox_container_id": None}, as_node="generate_fix")
        # otherwise (cleanup / error / PR steps) the id is harmless: cleanup_sandbox.remove is idempotent
    log.info("agent.paused", next_nodes=sorted(next_nodes))
    final = (await graph.aget_state(config)).values
    return AgentState(**final).model_copy(update={"terminal_status": PAUSED})


async def _execute(graph: Any, job_id: str, initial_state: dict[str, Any], should_pause: PauseCheck | None = None) -> AgentState:
    """Start a new run, or resume the thread if a previous run stopped mid-graph (crash or pause)."""
    config = {"configurable": {"thread_id": job_id}, "recursion_limit": RECURSION_LIMIT}
    snapshot = await graph.aget_state(config)
    same_run = (snapshot.values or {}).get("run_id", "") == initial_state.get("run_id", "")
    if snapshot.next and same_run:  # incomplete checkpoint of THIS run: continue from the last finished node
        log.info("agent.resume", next_nodes=list(snapshot.next))
        graph_input: Any = None
    else:
        graph_input = AgentState(**initial_state)
    if await _drive(graph, graph_input, config, should_pause):
        return await _park(graph, config)
    return AgentState(**(await graph.aget_state(config)).values)


async def run_fix_agent(
    job_id: str, initial_state: dict[str, Any], *, checkpointer: Any | None = None, should_pause: PauseCheck | None = None
) -> AgentState:
    """Run (or resume) the fix agent for ``job_id``.

    Honors the global kill-switch: with ``AUTOMATION_ENABLED=false`` nothing runs and the
    returned state carries ``terminal_status="DISABLED"``. ``checkpointer`` may be injected
    (tests use an in-memory saver); otherwise PostgreSQL is used.

    ``should_pause`` is polled after every graph step; when it returns ``True`` the run stops, its sandbox
    is removed, and the returned state has ``terminal_status="PAUSED"``. Calling again with the same
    ``run_id`` resumes it.
    """
    state_input = {"max_fix_attempts": settings.MAX_FIX_ATTEMPTS, **initial_state, "job_id": job_id}
    with bind_job(job_id, cve_id=state_input.get("cve_id"), repo=state_input.get("repo_name")):
        if not settings.AUTOMATION_ENABLED:
            log.warning("agent.disabled", reason="AUTOMATION_ENABLED=false")
            return AgentState(
                **state_input,
                terminal_status="DISABLED",
                audit_events=[make_event("JOB_FAILED", {"reason": "automation disabled (kill-switch)"})],
            )

        if checkpointer is not None:
            return await _execute(build_fix_agent_graph(checkpointer), job_id, state_input, should_pause)

        async with AsyncPostgresSaver.from_conn_string(settings.checkpoint_database_url) as saver:
            if settings.checkpoint_setup_on_start:
                await saver.setup()  # local dev only; Alembic owns the DDL elsewhere
            return await _execute(build_fix_agent_graph(saver), job_id, state_input, should_pause)
