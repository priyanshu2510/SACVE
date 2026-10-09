"""Version comparison helpers (PEP 440 first; falls back to numeric-segment comparison)."""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

_LEADING_V = re.compile(r"^[vV]")


def _normalise(version: str) -> str:
    return _LEADING_V.sub("", version.strip())


def _parse(version: str) -> Version | None:
    try:
        return Version(_normalise(version))
    except InvalidVersion:
        return None


def _numeric_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", _normalise(version)))


def compare_versions(a: str, b: str) -> int:
    """Return -1, 0 or 1 as ``a`` is less than, equal to, or greater than ``b``."""
    va, vb = _parse(a), _parse(b)
    if va is not None and vb is not None:
        return (va > vb) - (va < vb)
    ka, kb = _numeric_key(a), _numeric_key(b)
    return (ka > kb) - (ka < kb)


def versions_equal(a: str, b: str) -> bool:
    """True if two version strings denote the same version (``v1.2`` == ``1.2.0``)."""
    return compare_versions(a, b) == 0


def is_less_than(a: str, b: str) -> bool:
    """True if ``a`` < ``b``."""
    return compare_versions(a, b) < 0
