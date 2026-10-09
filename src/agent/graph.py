"""Fix-agent StateGraph definition.

    assemble_context -> assess_reachability -> generate_fix -> score_confidence -> run_sandbox
      -> run_pre_tests -> apply_patch -> resolve_dependencies -> run_post_tests -> run_security_scan
      -> cleanup_sandbox -> create_pr -> notify_owners -> write_audit

Repair loop: a patch that does not apply, a dependency-resolution failure, a test regression or a
CVE still present routes back to ``generate_fix`` while ``fix_attempt < max_fix_attempts``; the sandbox
is reused (``apply_patch`` resets it). Exhausted attempts end ``BLOCKED`` via ``cleanup_sandbox``.

Every terminal path ends in ``write_audit``, which is not routed to ``handle_error`` on failure: a failing
flush leaves the checkpoint before it so the Celery retry resumes exactly there.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from src.agent import routing
from src.agent.nodes import (
    apply_patch,
    assemble_context,
    assess_reachability,
    cleanup_sandbox,
    create_pr,
    generate_fix,
    handle_error,
    notify_owners,
    resolve_dependencies,
    run_post_tests,
    run_pre_tests,
    run_sandbox,
    run_security_scan,
    score_confidence,
    write_audit,
)
from src.agent.state import AgentState

# One full pass is ~12 supersteps and each repair attempt adds ~6; LangGraph's default limit (25) is too tight.
RECURSION_LIMIT = 100


def build_fix_agent_graph(checkpointer: Any | None = None) -> Any:
    """Build and compile the fix-agent graph (checkpointed when ``checkpointer`` is given)."""
    graph = StateGraph(AgentState)

    nodes = {
        "assemble_context": assemble_context,
        "assess_reachability": assess_reachability,
        "generate_fix": generate_fix,
        "score_confidence": score_confidence,
        "run_sandbox": run_sandbox,
        "run_pre_tests": run_pre_tests,
        "apply_patch": apply_patch,
        "resolve_dependencies": resolve_dependencies,
        "run_post_tests": run_post_tests,
        "run_security_scan": run_security_scan,
        "cleanup_sandbox": cleanup_sandbox,
        "create_pr": create_pr,
        "notify_owners": notify_owners,
        "write_audit": write_audit,
        "handle_error": handle_error,
    }
    for name, fn in nodes.items():
        graph.add_node(name, fn)
    graph.set_entry_point("assemble_context")

    def branch(source: str, router: Any, targets: dict[str, Any]) -> None:
        graph.add_conditional_edges(source, router, {k: (END if v is END else v) for k, v in targets.items()})

    branch("assemble_context", routing.route_after_context,
           {"assess_reachability": "assess_reachability", "handle_error": "handle_error"})  # fmt: skip
    branch("assess_reachability", routing.route_after_reachability,
           {"generate_fix": "generate_fix", "write_audit": "write_audit", "handle_error": "handle_error"})  # fmt: skip
    branch("generate_fix", routing.route_after_fix,
           {"score_confidence": "score_confidence", "handle_error": "handle_error"})  # fmt: skip
    branch("score_confidence", routing.route_after_scoring,
           {"run_sandbox": "run_sandbox", "apply_patch": "apply_patch", "handle_error": "handle_error"})  # fmt: skip
    branch("run_sandbox", routing.route_after_sandbox,
           {"run_pre_tests": "run_pre_tests", "cleanup_sandbox": "cleanup_sandbox", "handle_error": "handle_error"})  # fmt: skip
    branch("run_pre_tests", routing.route_after_pre_tests,
           {"apply_patch": "apply_patch", "cleanup_sandbox": "cleanup_sandbox", "handle_error": "handle_error"})  # fmt: skip
    branch("apply_patch", routing.route_after_patch,
           {"resolve_dependencies": "resolve_dependencies", "generate_fix": "generate_fix",
            "cleanup_sandbox": "cleanup_sandbox", "handle_error": "handle_error"})  # fmt: skip
    branch("resolve_dependencies", routing.route_after_resolve,
           {"run_post_tests": "run_post_tests", "generate_fix": "generate_fix",
            "cleanup_sandbox": "cleanup_sandbox", "handle_error": "handle_error"})  # fmt: skip
    branch("run_post_tests", routing.route_after_post_tests,
           {"run_security_scan": "run_security_scan", "generate_fix": "generate_fix",
            "cleanup_sandbox": "cleanup_sandbox", "handle_error": "handle_error"})  # fmt: skip
    branch("run_security_scan", routing.route_after_scan,
           {"cleanup_sandbox": "cleanup_sandbox", "generate_fix": "generate_fix", "handle_error": "handle_error"})  # fmt: skip
    branch("cleanup_sandbox", routing.route_after_cleanup, {"create_pr": "create_pr", "write_audit": "write_audit"})

    graph.add_edge("handle_error", "cleanup_sandbox")  # always tear the sandbox down
    branch("create_pr", routing.route_after_pr,
           {"notify_owners": "notify_owners", "write_audit": "write_audit", "handle_error": "handle_error"})  # fmt: skip
    graph.add_edge("notify_owners", "write_audit")
    graph.add_edge("write_audit", END)
    return graph.compile(checkpointer=checkpointer)
