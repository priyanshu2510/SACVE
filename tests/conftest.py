"""Shared fixtures."""

from __future__ import annotations

from typing import Any

import pytest

from src.agent.state import AgentState


@pytest.fixture
def make_state():
    """Factory for a valid :class:`AgentState` with per-test overrides."""

    def _make(**overrides: Any) -> AgentState:
        base: dict[str, Any] = {
            "job_id": "job-1",
            "cve_id": "CVE-2024-35195",
            "repo_name": "org/api-gateway",
            "ecosystem": "pip",
            "affected_package": "requests",
            "installed_version": "2.31.0",
            "target_version": "2.32.0",
            "manifest_file_path": "requirements.txt",
            "cvss_score": 5.6,
            "severity": "MEDIUM",
        }
        base.update(overrides)
        return AgentState(**base)

    return _make


class FakeContentSource:
    """In-memory :class:`GitHubContentSource` for tests."""

    def __init__(
        self,
        files: dict[str, str] | None = None,
        search: dict[str, list[str]] | None = None,
        release_notes: str | None = None,
        search_error: Exception | None = None,
        notes_error: Exception | None = None,
    ) -> None:
        self.files = files or {}
        self.search = search or {}
        self.release_notes = release_notes
        self.search_error = search_error
        self.notes_error = notes_error
        self.calls: list[tuple[str, tuple]] = []

    async def get_file(self, repo, path, ref=None):
        self.calls.append(("get_file", (repo, path)))
        return self.files.get(path)

    async def search_code(self, repo, query, language=None, limit=10):
        self.calls.append(("search_code", (repo, query, language)))
        if self.search_error:
            raise self.search_error
        return list(self.search.get(query, []))

    async def get_release_notes(self, package, ecosystem, version):
        self.calls.append(("get_release_notes", (package, ecosystem, version)))
        if self.notes_error:
            raise self.notes_error
        return self.release_notes


@pytest.fixture
def cve_context():
    """Advisory facts for requests / CVE-2024-35195 (fix 2.32.0)."""
    from src.agent.deps import CVEContext

    return CVEContext(
        cve_id="CVE-2024-35195",
        title="Requests Session verify=False persists",
        description="When making requests through a Session, if the first request uses verify=False ...",
        affected_versions=["< 2.32.0"],
        fixed_version="2.32.0",
        fixed_versions=["2.32.0"],
    )


async def _default_thresholds() -> tuple[int, int]:
    return 85, 70


@pytest.fixture
def agent_deps(cve_context):
    """Install fake deps as a context manager: ``with agent_deps(source, sandbox=..., pr=..., ...)``.

    Defaults: happy-path sandbox mirroring ``source.files``, a recording PR service, in-memory
    idempotency / audit stores and a dispatcher with a single recording channel. The created fakes are
    available on the yielded ``Deps`` object.
    """
    from contextlib import contextmanager
    from types import SimpleNamespace

    from src.agent.deps import override_deps
    from src.services.notifications.dispatcher import NotificationDispatcher
    from tests.fakes import (
        FakePRService, FakeSandboxManager, MemoryAuditStore, MemoryIdempotency, MemoryNotificationLog, RecordingHandler,
    )

    @contextmanager
    def install(source: FakeContentSource, cve=cve_context, llm_transport=None, sandbox=None, pr=None, audit=None,
                idempotency=None, handlers=None):  # fmt: skip
        async def loader(cve_id, ecosystem, package):
            return cve

        deps = SimpleNamespace(
            source=source,
            sandbox=sandbox or FakeSandboxManager(source.files),
            pr=pr or FakePRService(),
            audit=audit or MemoryAuditStore(),
            idempotency=idempotency or MemoryIdempotency(),
            notification_log=MemoryNotificationLog(),
            handlers=handlers if handlers is not None else [RecordingHandler("teams")],
        )
        deps.dispatcher = NotificationDispatcher(deps.handlers, deps.idempotency, deps.notification_log)
        with override_deps(
            content_source=source, cve_loader=loader, llm_transport=llm_transport, sandbox_manager=deps.sandbox,
            pr_service=deps.pr, idempotency=deps.idempotency, audit_store=deps.audit, dispatcher=deps.dispatcher,
            tier_thresholds=_default_thresholds,
        ):  # fmt: skip
            yield deps

    return install


@pytest.fixture
async def migrated_db(monkeypatch):
    """Scratch Postgres database with all Alembic migrations applied; skips if Postgres is unreachable.

    Patches ``settings.DATABASE_URL`` to point at the scratch DB and yields its name.
    """
    import asyncio
    import uuid
    from pathlib import Path

    import psycopg
    from alembic import command
    from alembic.config import Config

    from src.core.config import settings

    root = Path(__file__).resolve().parents[1]
    name = f"cve_test_{uuid.uuid4().hex[:8]}"
    admin_dsn = settings.checkpoint_database_url.rsplit("/", 1)[0] + "/postgres"
    try:
        admin = psycopg.connect(admin_dsn, autocommit=True, connect_timeout=2)
    except psycopg.OperationalError:
        pytest.skip("Postgres not reachable")
    admin.execute(f'CREATE DATABASE "{name}"')
    monkeypatch.setattr(settings, "DATABASE_URL", settings.DATABASE_URL.rsplit("/", 1)[0] + f"/{name}")
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    import src.core.database as dbmod

    dbmod._engine = dbmod._sessionmaker = None  # the app engine is cached per URL: rebuild it for the scratch DB
    try:
        # alembic's env.py calls asyncio.run, so it must run off the event-loop thread
        await asyncio.to_thread(command.upgrade, cfg, "head")
        yield name
    finally:
        if dbmod._engine is not None:
            await dbmod._engine.dispose()
        dbmod._engine = dbmod._sessionmaker = None
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()
