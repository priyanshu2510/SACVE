"""Secret detection and redaction for anything persisted to audit tables / S3 / LLM snapshots."""

from __future__ import annotations

import re
from typing import Any

from src.core.config import settings

REDACTED = "[REDACTED]"

# Order matters: specific token shapes first, generic key=value last.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
)
# user:password@ credentials embedded in URLs (e.g. private pip index URLs).
_URL_CREDS = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")
# key = value / key: value where the key looks sensitive. Keeps the key, redacts the value.
_KEY_VALUE = re.compile(
    r"""(?ix)
    (?P<key>[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)[\w.-]*)
    (?P<sep>\s*[:=]\s*)
    (?P<quote>["']?)
    (?P<val>[^\s"'#,;]{6,})
    (?P=quote)
    """
)


def redact_text(text: str, *, force: bool = False) -> str:
    """Return ``text`` with detected secrets replaced by ``[REDACTED]``.

    No-ops when ``REDACT_SECRETS_IN_AUDIT`` is disabled unless ``force`` is set.
    """
    if not (force or settings.REDACT_SECRETS_IN_AUDIT):
        return text
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = _URL_CREDS.sub(lambda m: f"{m.group('scheme')}{REDACTED}@", text)
    return _KEY_VALUE.sub(
        lambda m: f"{m.group('key')}{m.group('sep')}{m.group('quote')}{REDACTED}{m.group('quote')}", text
    )


def redact_obj(obj: Any, *, force: bool = False) -> Any:
    """Recursively redact every string inside dicts / lists / tuples."""
    if isinstance(obj, str):
        return redact_text(obj, force=force)
    if isinstance(obj, dict):
        return {k: redact_obj(v, force=force) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v, force=force) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v, force=force) for v in obj)
    return obj
