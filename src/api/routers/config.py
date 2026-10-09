"""Runtime configuration: repository allow / block lists."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import Authed, get_session
from src.models.sync import SyncState
from src.schemas.api import RepoConfig, RepoConfigUpdate
from src.services.matcher.repo_filter import OVERRIDE_KEY, load_static_filter, save_override

router = APIRouter(prefix="/api/v1/config", tags=["config"], dependencies=Authed)


async def _effective(session: AsyncSession) -> RepoConfig:
    override = await session.get(SyncState, OVERRIDE_KEY)
    if override is not None:
        return RepoConfig(allowlist=list(override.value.get("allowlist", [])), blocklist=list(override.value.get("blocklist", [])), source="override")
    static = load_static_filter()
    return RepoConfig(allowlist=sorted(static.allowlist), blocklist=sorted(static.blocklist), source="static")


@router.get("/repos", response_model=RepoConfig)
async def get_repo_config(session: AsyncSession = Depends(get_session)) -> RepoConfig:
    """The effective allow / block lists (a runtime override, or the yaml + environment defaults)."""
    return await _effective(session)


@router.patch("/repos", response_model=RepoConfig)
async def update_repo_config(body: RepoConfigUpdate, session: AsyncSession = Depends(get_session)) -> RepoConfig:
    """Replace the allow and/or block list. Takes effect on the next matcher run; archived and ``cve-exempt`` repos stay excluded."""
    current = await _effective(session)
    allow = current.allowlist if body.allowlist is None else sorted({e.lower() for e in body.allowlist})
    block = current.blocklist if body.blocklist is None else sorted({e.lower() for e in body.blocklist})
    await save_override(session, allow, block)
    return RepoConfig(allowlist=allow, blocklist=block, source="override")
