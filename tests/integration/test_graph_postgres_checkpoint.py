"""The core graph against the real PostgreSQL checkpointer, using only the Alembic-created tables."""

import httpx
import psycopg
import pytest
from pydantic import SecretStr

from src.agent.runner import run_fix_agent
from src.core.config import settings
from src.utils import retry as retry_mod
from tests.conftest import FakeContentSource
from tests.integration.test_graph_core_run import APP, INITIAL, MANIFEST
from tests.llm_helpers import Recorder, chat, good

pytestmark = pytest.mark.db


async def test_run_checkpoints_to_postgres_without_setup(migrated_db, agent_deps, monkeypatch):
    monkeypatch.setattr("src.agent.nodes.fix_generator.default_settings.LLM_API_KEY", SecretStr("k"))
    monkeypatch.setattr(settings, "AUTOMATION_ENABLED", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "prod")  # setup() disabled: Alembic must have created the tables
    assert settings.checkpoint_setup_on_start is False

    async def _sleep(_: float) -> None:
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)
    src = FakeContentSource(
        files={"requirements.txt": MANIFEST, "app/client.py": APP},
        search={"requests": ["app/client.py"]},
    )
    with agent_deps(src, llm_transport=httpx.MockTransport(Recorder(chat(good())))):
        final = await run_fix_agent("job-pg-1", INITIAL | {"job_id": "job-pg-1"})
    assert final.terminal_status == "PR_RAISED" and final.fix_attempt == 1

    dsn = settings.checkpoint_database_url
    with psycopg.connect(dsn) as conn:
        (n,) = conn.execute("select count(*) from checkpoints where thread_id = 'job-pg-1'").fetchone()
        (m,) = conn.execute("select count(*) from checkpoint_migrations").fetchone()
    assert n >= 10 and m == 10  # setup() never ran, so no extra migration rows
