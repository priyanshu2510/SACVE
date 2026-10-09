"""Node 1: assemble the LLM context (CVE facts, manifest, importing source files, changelog)."""

from __future__ import annotations

import asyncio
import json
import math
from typing import Any

import structlog

from src.agent.deps import get_content_source, get_cve_loader
from src.agent.nodes._common import NodeError, agent_node, with_event
from src.agent.state import AgentState
from src.core.config import settings
from src.core.redaction import redact_text
from src.utils.packages import declared_in_manifest, import_names
from src.utils.version_compare import versions_equal

log = structlog.get_logger(__name__)

CHARS_PER_TOKEN = 4  # coarse estimate; the internal model's tokenizer is not known
MAX_SOURCE_FILES = 10
SEARCH_LIMIT = 10
MIN_USEFUL_TOKENS = 50
_SEARCH_LANGUAGE = {"pip": "python", "go": "go", "maven": "java", "nuget": "c#", "gem": "ruby"}


def estimate_tokens(text: str) -> int:
    """Rough token count (``len / 4``, rounded up)."""
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def truncate_to_tokens(text: str, max_tokens: int) -> tuple[str, bool]:
    """Cut ``text`` to roughly ``max_tokens`` at a line boundary; returns ``(text, was_truncated)``."""
    if estimate_tokens(text) <= max_tokens:
        return text, False
    cut = text[: max(0, max_tokens) * CHARS_PER_TOKEN]
    if "\n" in cut:
        cut = cut[: cut.rfind("\n")]
    return cut, True


async def _find_source_files(
    repo: str, ecosystem: str, package: str, manifest_path: str
) -> tuple[list[str], bool]:
    """Search for files that use the package; returns ``(paths, search_was_exhaustive)``."""
    source = get_content_source()
    language = _SEARCH_LANGUAGE.get(ecosystem)
    names = import_names(ecosystem, package)
    results = await asyncio.gather(
        *(source.search_code(repo, name, language=language, limit=SEARCH_LIMIT) for name in names),
        return_exceptions=True,
    )
    paths: list[str] = []
    exhaustive = True
    for name, result in zip(names, results):
        if isinstance(result, BaseException):
            log.warning("context.search_failed", query=name, error=str(result))
            exhaustive = False
            continue
        if len(result) >= SEARCH_LIMIT:
            exhaustive = False
        paths.extend(p for p in result if p != manifest_path)
    return list(dict.fromkeys(paths)), exhaustive


@agent_node("assemble_context")
async def assemble_context(state: AgentState) -> dict[str, Any]:
    """Fetch and budget everything the LLM needs.

    Fails (``error`` set) if the CVE is unknown, the manifest is missing, the supply-chain
    check rejects ``target_version``, or the non-negotiable context alone exceeds the budget.
    """
    source = get_content_source()
    cve = await get_cve_loader()(state.cve_id, state.ecosystem, state.affected_package)
    if cve is None:
        raise NodeError(f"{state.cve_id} not found in the CVE database")

    advisory_verified = any(versions_equal(state.target_version, v) for v in cve.fixed_versions)
    if settings.SUPPLY_CHAIN_VERIFY and not advisory_verified:
        raise NodeError(
            f"supply-chain check failed: target_version {state.target_version} is not an advisory "
            f"fixed version for {state.affected_package} (advisory: {cve.fixed_versions or 'none'})"
        )

    manifest_raw = await source.get_file(state.repo_name, state.manifest_file_path)
    if manifest_raw is None:
        raise NodeError(f"manifest {state.manifest_file_path} not found in {state.repo_name}")
    manifest = redact_text(manifest_raw)

    paths, exhaustive = await _find_source_files(
        state.repo_name, state.ecosystem, state.affected_package, state.manifest_file_path
    )
    fetched = await asyncio.gather(
        *(source.get_file(state.repo_name, p) for p in paths[:MAX_SOURCE_FILES]), return_exceptions=True
    )
    candidates: list[tuple[str, str]] = []
    for path, content in zip(paths[:MAX_SOURCE_FILES], fetched):
        if isinstance(content, BaseException):
            log.warning("context.file_fetch_failed", path=path, error=str(content))
            exhaustive = False
        elif content is not None:
            candidates.append((path, redact_text(content)))
    if len(paths) > MAX_SOURCE_FILES:
        exhaustive = False

    try:
        changelog_raw = await source.get_release_notes(state.affected_package, state.ecosystem, state.target_version)
    except Exception as exc:  # noqa: BLE001 - changelog is optional context
        log.warning("context.changelog_failed", error=str(exc))
        changelog_raw = None

    cve_block: dict[str, Any] = {
        "cve_id": state.cve_id,
        "title": cve.title,
        "description": redact_text(cve.description or ""),
        "ecosystem": state.ecosystem,
        "package": state.affected_package,
        "installed_version": state.installed_version,
        "target_version": state.target_version,
        "affected_versions": cve.affected_versions,
        "fixed_version": cve.fixed_version,
        "fixed_versions": cve.fixed_versions,
        "advisory_fix_verified": advisory_verified,
    }

    # Budget: CVE facts + manifest are never truncated; then source files; changelog gets the rest.
    budget = settings.LLM_CONTEXT_MAX_TOKENS
    used = estimate_tokens(json.dumps(cve_block)) + estimate_tokens(manifest)
    if used > budget:
        raise NodeError(f"context too large: CVE facts + manifest need ~{used} tokens (budget {budget})")

    source_files: list[dict[str, Any]] = []
    omitted: list[str] = []
    truncated_any = False
    for path, content in candidates:
        remaining = budget - used
        if remaining < MIN_USEFUL_TOKENS:
            omitted.append(path)
            continue
        text, was_cut = truncate_to_tokens(content, remaining)
        source_files.append({"path": path, "content": text, "truncated": was_cut})
        used += estimate_tokens(text)
        truncated_any = truncated_any or was_cut

    changelog: str | None = None
    if changelog_raw:
        remaining = budget - used
        if remaining >= MIN_USEFUL_TOKENS:
            changelog, was_cut = truncate_to_tokens(redact_text(changelog_raw), remaining)
            used += estimate_tokens(changelog)
            truncated_any = truncated_any or was_cut
        else:
            truncated_any = True

    payload: dict[str, Any] = {
        "cve": cve_block,
        "manifest": {"path": state.manifest_file_path, "content": manifest},
        "source_files": source_files,
        "omitted_source_paths": omitted,
        "changelog": changelog,
        "file_allowlist": [state.manifest_file_path, *(f["path"] for f in source_files)],
        "manifest_declares_package": declared_in_manifest(manifest, state.affected_package),
        # True only if every importing file was found, fetched and sent in full.
        "source_search_complete": exhaustive and not omitted and not any(f["truncated"] for f in source_files),
        "truncated": truncated_any or bool(omitted),
    }
    return {
        "context_payload": payload,
        "context_token_count": used,
        "audit_events": with_event(
            state,
            "CONTEXT_ASSEMBLED",
            {
                "manifest": state.manifest_file_path,
                "source_files": [f["path"] for f in source_files],
                "omitted_source_paths": omitted,
                "token_count": used,
                "truncated": payload["truncated"],
                "advisory_fix_verified": advisory_verified,
                "changelog_included": changelog is not None,
            },
        ),
    }
