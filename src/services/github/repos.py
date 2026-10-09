"""Organisation repository enumeration and sync into the ``repos`` table."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.job import Repo
from src.services.github.client import PyGithubBase

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class RepoInfo:
    """What the platform needs to know about a repository."""

    full_name: str
    default_branch: str = "main"
    language: str | None = None
    archived: bool = False
    topics: list[str] = field(default_factory=list)


@runtime_checkable
class OrgRepoLister(Protocol):
    """Enumerates the organisation's repositories."""

    async def list_repos(self, org: str) -> list[RepoInfo]:
        """All repositories visible to the token."""


class PyGithubRepoLister(PyGithubBase):
    """PyGithub-backed lister (bulk/org operations use PyGithub per the design)."""

    async def list_repos(self, org: str) -> list[RepoInfo]:
        """List every repo in ``org`` including archived ones (the filter decides)."""

        def _list() -> list[RepoInfo]:
            return [
                RepoInfo(r.full_name, r.default_branch or "main", r.language, bool(r.archived), list(r.get_topics()))
                for r in self._gh.get_organization(org).get_repos(type="all")
            ]

        return await self._call(_list)


async def sync_repos(session: AsyncSession, infos: list[RepoInfo]) -> dict[str, int]:
    """Upsert ``infos`` into ``repos`` (never deletes: removed repos keep their history)."""
    existing = {r.full_name.lower(): r for r in (await session.execute(select(Repo))).scalars()}
    created = updated = 0
    for info in infos:
        row = existing.get(info.full_name.lower())
        if row is None:
            session.add(Repo(full_name=info.full_name, default_branch=info.default_branch, language=info.language,
                             archived=info.archived, topics=info.topics))  # fmt: skip
            created += 1
        elif (row.default_branch, row.language, row.archived, row.topics) != (info.default_branch, info.language, info.archived, info.topics):
            row.default_branch, row.language, row.archived, row.topics = info.default_branch, info.language, info.archived, info.topics
            updated += 1
    await session.flush()
    log.info("repos.synced", created=created, updated=updated, total=len(infos))
    return {"created": created, "updated": updated, "total": len(infos)}
