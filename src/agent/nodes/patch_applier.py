"""Node 7: apply the LLM's file changes inside the sandbox."""

from __future__ import annotations

from typing import Any

from src.agent.deps import get_sandbox_manager
from src.agent.nodes._common import NodeError, agent_node, make_event, record_failure
from src.agent.state import AgentState


@agent_node("apply_patch")
async def apply_patch(state: AgentState) -> dict[str, Any]:
    """Reset the workspace, then replace each change's ``original_content`` with ``new_content``.

    The reset makes the node idempotent and gives every repair attempt a clean checkout. Files are
    written through a tar upload (no shell quoting). A section that is missing or ambiguous in the
    real file is a repairable failure: the LLM is told and tries again.
    """
    if not state.sandbox_container_id or not state.file_changes:
        raise NodeError("apply_patch requires a sandbox and file changes")
    sandbox = await get_sandbox_manager().attach(state.sandbox_container_id)
    await sandbox.reset_workspace()

    patched: dict[str, str] = {}
    for change in state.file_changes:
        current = patched.get(change.file_path)
        if current is None:
            current = await sandbox.read_file(change.file_path)
        if current is None:
            return record_failure(state, f"{change.file_path} does not exist in the repository")
        occurrences = current.count(change.original_content)
        if occurrences == 0:
            return record_failure(
                state, f"original_content for {change.file_path} was not found in the file (it must match exactly)"
            )
        if occurrences > 1:
            return record_failure(
                state,
                f"original_content for {change.file_path} matches {occurrences} places; "
                "include more surrounding lines so it is unique",
            )
        patched[change.file_path] = current.replace(change.original_content, change.new_content, 1)

    for path, content in patched.items():
        await sandbox.write_file(path, content)
    return {
        "audit_events": [*state.audit_events, make_event("PATCH_APPLIED", {"files": sorted(patched), "attempt": state.fix_attempt})]
    }
