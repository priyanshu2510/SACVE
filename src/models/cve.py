"""CVE ORM models: normalised record, affected packages, raw feed responses."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, String, Text, UniqueConstraint, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base


class CVE(Base):
    """A normalised CVE (canonical key: ``cve_id``)."""

    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str | None] = mapped_column(String(16))
    cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32))
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    affected_packages: Mapped[list[CVEAffectedPackage]] = relationship(
        back_populates="cve", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_cves_severity", "severity"),)


class CVEAffectedPackage(Base):
    """A package/ecosystem affected by a CVE, with version ranges and fix version."""

    __tablename__ = "cve_affected_packages"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.cve_id", ondelete="CASCADE"))
    ecosystem: Mapped[str] = mapped_column(String(16))
    package_name: Mapped[str] = mapped_column(String(512))
    affected_versions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    fixed_version: Mapped[str | None] = mapped_column(String(128))

    cve: Mapped[CVE] = relationship(back_populates="affected_packages")

    __table_args__ = (
        UniqueConstraint("cve_id", "ecosystem", "package_name", name="uq_cve_pkg"),
        Index("ix_cve_pkg_lookup", "ecosystem", "package_name"),
    )


class CVERawFeed(Base):
    """Raw feed response as received from a source (append-only history)."""

    __tablename__ = "cve_raw_feeds"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
