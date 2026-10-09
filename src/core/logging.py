"""structlog setup: JSON logs with ``job_id`` correlation carried via contextvars."""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager

import structlog


def configure_logging(level: str = "INFO") -> None:
    """Configure structlog (JSON renderer) and the stdlib root logger."""
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper())
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        cache_logger_on_first_use=True,
    )


@contextmanager
def bind_job(job_id: str, **extra: object) -> Iterator[None]:
    """Bind ``job_id`` (the end-to-end correlation id) to every log line inside the block."""
    structlog.contextvars.bind_contextvars(job_id=job_id, **extra)
    try:
        yield
    finally:
        structlog.contextvars.unbind_contextvars("job_id", *extra.keys())
