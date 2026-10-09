"""Reachability triage: is the vulnerable package actually used by the repository's code?

v1 is a conservative static check for pip. It only concludes "unreachable" when it can
positively rule usage out; every uncertainty (transitive dependency, incomplete search,
dynamic imports, unparsable files) resolves to "reachable" so a real vulnerability is never
silently skipped. Symbol-level analysis (affected functions) needs advisory symbol data and
is a later enhancement.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from src.agent.nodes._common import agent_node, with_event
from src.agent.routing import NOT_REACHABLE
from src.agent.state import AgentState
from src.core.config import settings
from src.utils.packages import import_names

_DYNAMIC_IMPORT = re.compile(r"\b(importlib|__import__|import_module)\b")


def _matches(module: str, names: list[str]) -> bool:
    return any(module == n or module.startswith(n + ".") for n in names)


def find_python_imports(source: str, names: list[str]) -> list[dict[str, Any]]:
    """Return ``{line, statement}`` for each import of any of ``names``. Raises ``SyntaxError``."""
    hits: list[dict[str, Any]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            if any(_matches(alias.name, names) for alias in node.names):
                hits.append({"line": node.lineno, "statement": ast.unparse(node)})
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if _matches(node.module, names):
                hits.append({"line": node.lineno, "statement": ast.unparse(node)})
    return hits


def analyse_python(context: dict[str, Any], names: list[str]) -> tuple[bool, dict[str, Any]]:
    """Return ``(reachable, evidence)`` for a pip package given the assembled context."""
    importing: dict[str, list[dict[str, Any]]] = {}
    parse_errors: list[str] = []
    dynamic: list[str] = []
    for f in context.get("source_files", []):
        path, text = f["path"], f["content"]
        if not path.endswith(".py"):
            continue
        try:
            hits = find_python_imports(text, names)
        except SyntaxError:
            parse_errors.append(path)
            continue
        if hits:
            importing[path] = hits
        if _DYNAMIC_IMPORT.search(text):
            dynamic.append(path)

    evidence: dict[str, Any] = {
        "method": "python-ast-imports",
        "import_names": names,
        "importing_files": importing,
        "parse_errors": parse_errors,
        "dynamic_import_files": dynamic,
        "source_search_complete": bool(context.get("source_search_complete")),
        "manifest_declares_package": bool(context.get("manifest_declares_package")),
    }
    if importing:
        evidence["reason"] = "package is imported"
        return True, evidence
    if parse_errors:
        evidence["reason"] = "some files could not be parsed; cannot rule out usage"
        return True, evidence
    if dynamic:
        evidence["reason"] = "dynamic imports present; cannot rule out usage"
        return True, evidence
    if not evidence["manifest_declares_package"]:
        evidence["reason"] = "transitive dependency; direct imports do not prove it is unused"
        return True, evidence
    if not evidence["source_search_complete"]:
        evidence["reason"] = "source search incomplete; cannot rule out usage"
        return True, evidence
    evidence["reason"] = "direct dependency with no imports in any repository source file"
    return False, evidence


@agent_node("assess_reachability")
async def assess_reachability(state: AgentState) -> dict[str, Any]:
    """Set ``reachable`` / ``reachability_evidence``; in ``enforce`` mode an unreachable CVE ends the job."""
    if state.ecosystem == "pip":
        reachable, evidence = analyse_python(state.context_payload or {}, import_names("pip", state.affected_package))
    else:
        reachable, evidence = True, {"method": "not_implemented", "reason": f"no analyser for {state.ecosystem}"}

    update: dict[str, Any] = {
        "reachable": reachable,
        "reachability_evidence": evidence,
        "audit_events": with_event(
            state,
            "REACHABILITY_ASSESSED",
            {"reachable": reachable, "mode": settings.REACHABILITY_MODE, "reason": evidence.get("reason"),
             "importing_files": sorted(evidence.get("importing_files", {}))},
        ),  # fmt: skip
    }
    if not reachable and settings.REACHABILITY_MODE == "enforce":
        update["terminal_status"] = NOT_REACHABLE
    return update
