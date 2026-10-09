"""Alembic upgrade/downgrade against a scratch database. Skipped when Postgres is unreachable."""

from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config

from src.core.config import settings

pytestmark = pytest.mark.db

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_TABLES = {
    "cves", "cve_affected_packages", "cve_raw_feeds", "repos", "remediation_jobs", "cve_repo_impact",
    "idempotency_keys", "audit_events", "pr_outcomes", "sboms", "notification_log",
    "checkpoints", "checkpoint_blobs", "checkpoint_writes", "checkpoint_migrations",
}  # fmt: skip


def _admin_dsn() -> str:
    return settings.checkpoint_database_url.rsplit("/", 1)[0] + "/postgres"


@pytest.fixture
def scratch_db(monkeypatch):
    name = f"cve_mig_{uuid.uuid4().hex[:8]}"
    try:
        admin = psycopg.connect(_admin_dsn(), autocommit=True, connect_timeout=2)
    except psycopg.OperationalError:
        pytest.skip("Postgres not reachable")
    admin.execute(f'CREATE DATABASE "{name}"')
    base = settings.DATABASE_URL.rsplit("/", 1)[0]
    monkeypatch.setattr(settings, "DATABASE_URL", f"{base}/{name}")
    try:
        yield name
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()


def _tables(db: str) -> set[str]:
    dsn = settings.checkpoint_database_url.rsplit("/", 1)[0] + f"/{db}"
    with psycopg.connect(dsn) as conn:
        rows = conn.execute("select tablename from pg_tables where schemaname='public'").fetchall()
    return {r[0] for r in rows}


def test_upgrade_downgrade_roundtrip_and_audit_is_append_only(scratch_db):
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))

    command.upgrade(cfg, "head")
    assert EXPECTED_TABLES <= _tables(scratch_db)

    dsn = settings.checkpoint_database_url.rsplit("/", 1)[0] + f"/{scratch_db}"
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("insert into audit_events(event_type, payload) values ('JOB_QUEUED', '{}')")
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("update audit_events set event_type = 'X'")
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("delete from audit_events")
        versions = conn.execute("select count(*) from checkpoint_migrations").fetchone()[0]
    assert versions >= 10  # setup() will be a no-op

    command.downgrade(cfg, "base")
    assert not (EXPECTED_TABLES & _tables(scratch_db))
