"""Human-feedback calibration: tune the confidence tiers against what reviewers actually did with the PRs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.audit import PROutcome, PROutcomeKind
from src.models.sync import SyncState
from src.services.github.pr_description import DEFAULT_HIGH, DEFAULT_MEDIUM

log = structlog.get_logger(__name__)

KEY = "confidence_calibration"
MIN_SAMPLES = 30  # below this the defaults are kept: a handful of PRs says nothing
MIN_TIER_SAMPLES = 10
TARGET_CLEAN_RATE = {"high": 0.90, "medium": 0.70}  # share of PRs merged without edits a tier should achieve
BOUNDS = (50, 95)


def find_threshold(samples: list[tuple[int, bool]], target: float, default: int, upper: int | None = None) -> int:
    """Smallest score ``t`` such that PRs scoring in ``[t, upper)`` were merged clean at least ``target`` of the time.

    The band is judged on its own (not cumulatively), so strong high-score PRs cannot hide a weak band
    below them. Needs ``MIN_TIER_SAMPLES`` PRs in the band; falls back to ``default`` when no score qualifies.
    """
    pool = [(score, clean) for score, clean in samples if upper is None or score < upper]
    best: int | None = None
    for t in sorted({score for score, _ in pool}, reverse=True):
        band = [clean for score, clean in pool if score >= t]
        if len(band) >= MIN_TIER_SAMPLES and sum(band) / len(band) >= target:
            best = t
    return default if best is None else best


def compute(samples: list[tuple[int, bool]]) -> dict[str, Any]:
    """Thresholds from ``(predicted_score, merged_clean)`` samples."""
    base: dict[str, Any] = {"high": DEFAULT_HIGH, "medium": DEFAULT_MEDIUM, "samples": len(samples), "calibrated": False}
    if len(samples) < MIN_SAMPLES:
        return base | {"reason": f"need {MIN_SAMPLES} reviewed PRs, have {len(samples)}"}
    low, top = BOUNDS
    high = min(max(find_threshold(samples, TARGET_CLEAN_RATE["high"], DEFAULT_HIGH), low + 1), top)
    medium = min(max(find_threshold(samples, TARGET_CLEAN_RATE["medium"], DEFAULT_MEDIUM, upper=high), low), high - 1)
    tiers = {
        "high": [c for s, c in samples if s >= high],
        "medium": [c for s, c in samples if medium <= s < high],
        "low": [c for s, c in samples if s < medium],
    }
    rates = {k: (round(sum(v) / len(v), 3) if v else None) for k, v in tiers.items()}
    return base | {"high": high, "medium": medium, "calibrated": True, "clean_rate_by_tier": rates, "tier_sizes": {k: len(v) for k, v in tiers.items()}}


async def recalibrate(session: AsyncSession) -> dict[str, Any]:
    """Recompute the tier thresholds from recorded PR outcomes and persist them."""
    rows = (await session.execute(select(PROutcome.predicted_confidence, PROutcome.outcome).where(PROutcome.predicted_confidence.is_not(None)))).all()
    samples = [(int(score), outcome == PROutcomeKind.MERGED_CLEAN.value) for score, outcome in rows]
    result = compute(samples) | {"computed_at": datetime.now(timezone.utc).isoformat()}
    row = await session.get(SyncState, KEY)
    if row is None:
        session.add(SyncState(key=KEY, value=result))
    else:
        row.value = result
    log.info("calibration.done", **{k: v for k, v in result.items() if k in ("high", "medium", "samples", "calibrated")})
    return result


async def load_thresholds(session: AsyncSession) -> tuple[int, int]:
    """Current ``(high, medium)`` tier cut-offs (defaults until calibration has enough data)."""
    row = await session.get(SyncState, KEY)
    if row is None or not row.value.get("calibrated"):
        return DEFAULT_HIGH, DEFAULT_MEDIUM
    return int(row.value["high"]), int(row.value["medium"])
