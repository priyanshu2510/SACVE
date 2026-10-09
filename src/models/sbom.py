"""SBOM ORM model."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.core.database import Base


class SBOM(Base):
    """CycloneDX SBOM snapshot for a repo (document in JSONB, copy in S3)."""

    __tablename__ = "sboms"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    repo_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repos.id"))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(32), default="cyclonedx-json")
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)
    s3_key: Mapped[str | None] = mapped_column(String(512))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_sbom_repo", "repo_id", "generated_at"),)
