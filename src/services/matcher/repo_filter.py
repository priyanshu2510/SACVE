"""Which repositories are in scope: allow/block lists (yaml + env + runtime override), archived and exempt repos."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import Settings, settings as default_settings
from src.models.sync import SyncState

EXEMPT_TOPIC = "cve-exempt"
OVERRIDE_KEY = "repo_filter_override"
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "repos.yaml"


def _norm(entries: list[str]) -> set[str]:
    return {e.strip().lower() for e in entries if e and e.strip()}


@dataclass(frozen=True)
class RepoFilter:
    """Decides whether a repository is scanned and remediated. Blocklist beats allowlist."""

    allowlist: frozenset[str] = field(default_factory=frozenset)  # empty = every repo
    blocklist: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_lists(cls, allow: list[str], block: list[str]) -> RepoFilter:
        """Build from raw lists (``name`` or ``org/name`` entries, case-insensitive)."""
        return cls(frozenset(_norm(allow)), frozenset(_norm(block)))

    def check(self, full_name: str, *, archived: bool = False, topics: list[str] | None = None) -> tuple[bool, str]:
        """Return ``(allowed, reason)``; archived and ``cve-exempt`` repos are always excluded."""
        if archived:
            return False, "archived"
        if EXEMPT_TOPIC in {t.lower() for t in topics or []}:
            return False, "cve-exempt"
        names = {full_name.lower(), full_name.split("/")[-1].lower()}
        if names & self.blocklist:
            return False, "blocklisted"
        if self.allowlist and not names & self.allowlist:
            return False, "not allowlisted"
        return True, "ok"

    def allows(self, full_name: str, *, archived: bool = False, topics: list[str] | None = None) -> bool:
        """Boolean form of :meth:`check`."""
        return self.check(full_name, archived=archived, topics=topics)[0]


def load_static_filter(cfg: Settings | None = None, path: Path = DEFAULT_CONFIG_PATH) -> RepoFilter:
    """``config/repos.yaml`` merged with ``REPO_ALLOWLIST`` / ``REPO_BLOCKLIST``."""
    cfg = cfg or default_settings
    data: dict[str, Any] = yaml.safe_load(path.read_text()) if path.exists() else {}
    data = data or {}
    allow = [*(data.get("allowlist") or []), *cfg.REPO_ALLOWLIST]
    block = [*(data.get("blocklist") or []), *cfg.REPO_BLOCKLIST]
    return RepoFilter.from_lists(allow, block)


async def load_repo_filter(session: AsyncSession, cfg: Settings | None = None) -> RepoFilter:
    """Static filter, replaced by the runtime override (set through the Control API) when one exists."""
    override = await session.get(SyncState, OVERRIDE_KEY)
    if override is not None:
        return RepoFilter.from_lists(override.value.get("allowlist", []), override.value.get("blocklist", []))
    return load_static_filter(cfg)


async def save_override(session: AsyncSession, allowlist: list[str], blocklist: list[str]) -> None:
    """Persist a runtime allow/block list override."""
    row = await session.get(SyncState, OVERRIDE_KEY)
    value = {"allowlist": allowlist, "blocklist": blocklist}
    if row is None:
        session.add(SyncState(key=OVERRIDE_KEY, value=value))
    else:
        row.value = value
