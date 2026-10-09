"""LangGraph checkpoint tables

Reuses the DDL shipped with the pinned ``langgraph-checkpoint-postgres`` so the schema
stays in sync with the library, and records every version in ``checkpoint_migrations``
so ``AsyncPostgresSaver.setup()`` is a no-op afterwards (it is disabled outside local).

Revision ID: 0002
Revises: 0001
"""
from typing import Sequence, Union

from alembic import op
from langgraph.checkpoint.postgres import PostgresSaver

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for ddl in PostgresSaver.MIGRATIONS:
        # CREATE INDEX CONCURRENTLY cannot run inside Alembic's transaction; the tables
        # are empty at this point so a plain CREATE INDEX is equivalent.
        op.execute(ddl.replace("CONCURRENTLY ", ""))
    for version in range(len(PostgresSaver.MIGRATIONS)):
        op.execute(f"INSERT INTO checkpoint_migrations (v) VALUES ({version}) ON CONFLICT DO NOTHING")


def downgrade() -> None:
    for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints", "checkpoint_migrations"):
        op.execute(f"DROP TABLE IF EXISTS {table}")
