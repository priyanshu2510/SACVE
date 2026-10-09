from src.services.calibration import MIN_SAMPLES, compute, find_threshold


def make(clean_rate_by_score: dict[int, float], per_score: int = 20):
    """Exactly ``rate * per_score`` clean PRs at each score (deterministic, no sampling noise)."""
    return [(score, i < round(rate * per_score)) for score, rate in clean_rate_by_score.items() for i in range(per_score)]


def test_too_few_samples_keeps_defaults():
    out = compute([(90, True)] * (MIN_SAMPLES - 1))
    assert (out["high"], out["medium"], out["calibrated"]) == (85, 70, False) and "need" in out["reason"]


def test_thresholds_move_to_where_reviewers_actually_accept_prs():
    # reviewers merge clean from ~92 up, mostly accept from ~78 up, and edit/reject below
    samples = make({95: 1.0, 92: 1.0, 88: 0.8, 84: 0.8, 80: 0.75, 78: 0.75, 70: 0.4, 60: 0.2})
    out = compute(samples)
    assert out["calibrated"] and 84 <= out["high"] <= 95 and 70 < out["medium"] <= 80  # not the defaults (85 / 70)
    assert out["medium"] < out["high"]
    rates = out["clean_rate_by_tier"]
    assert rates["high"] >= 0.9 and rates["medium"] >= 0.7 and rates["low"] < 0.5  # every tier delivers what it promises
    assert sum(out["tier_sizes"].values()) == len(samples)


def test_a_great_track_record_lowers_the_bar_but_not_below_the_floor():
    out = compute(make({s: 1.0 for s in (95, 90, 85, 80, 75, 70, 65, 55, 40)}))
    assert out["medium"] == 50 and out["high"] == 51  # clamped at the floor, tiers stay ordered


def test_when_nothing_qualifies_the_default_is_kept():
    assert find_threshold([(90, False)] * 40, 0.9, 85) == 85
    assert find_threshold([(90, True)] * 5, 0.9, 85) == 85  # too few PRs at that score to trust


def test_medium_is_always_below_high():
    out = compute(make({95: 1.0, 90: 1.0, 85: 1.0, 80: 1.0, 75: 1.0}, per_score=10))
    assert out["medium"] < out["high"]


def test_a_weak_band_is_not_hidden_by_strong_scores_above_it():
    # 90s are always accepted, 60-70 mostly rejected: a cumulative rate would wrongly pull MEDIUM down to 60
    out = compute(make({95: 1.0, 90: 1.0, 85: 1.0, 70: 0.3, 60: 0.3}, per_score=20))
    assert out["medium"] == 70  # the weak 60-70 band never qualifies, so the default stays (not dragged down to 60)
