"""Shared plumbing for the Atlassian Cloud REST clients (basic auth, retries)."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from src.utils.retry import retry_async

log = structlog.get_logger(__name__)
_RETRYABLE = {429, 500, 502, 503, 504}


def retryable(exc: BaseException) -> bool:
    """Retry throttling, 5xx and transport errors; never 4xx client mistakes."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRYABLE
    return isinstance(exc, httpx.TransportError)


class AtlassianError(RuntimeError):
    """A non-retryable Atlassian API failure, carrying the status and Atlassian's own message."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status, self.message = status, message


def describe(resp: httpx.Response) -> str:
    """Short, secret-free description of an error response."""
    try:
        data = resp.json()
    except ValueError:
        return resp.text[:300]
    parts = [*data.get("errorMessages", []), *(f"{k}: {v}" for k, v in (data.get("errors") or {}).items())]
    return "; ".join(parts) or str(data.get("message", data))[:300]


class AtlassianClient:
    """Thin async wrapper: JSON in/out, retries on transient failures, :class:`AtlassianError` otherwise."""

    def __init__(self, base_url: str, user: str, token: str, client: httpx.AsyncClient | None = None, timeout: int = 30) -> None:
        self._base = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._auth = (user, token)

    @retry_async(max_retries=3, base_delay=1.0, retry_on=(httpx.HTTPError,), is_retryable=retryable)
    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        resp = await self._client.request(method, f"{self._base}{path}", auth=self._auth, headers={"Accept": "application/json"}, **kwargs)
        if resp.status_code in _RETRYABLE:
            resp.raise_for_status()
        return resp

    async def request(self, method: str, path: str, *, ok: tuple[int, ...] = (200, 201, 204), **kwargs: Any) -> Any:
        """Send and return parsed JSON (``None`` for empty bodies); raises :class:`AtlassianError` on other statuses."""
        resp = await self._send(method, path, **kwargs)
        if resp.status_code not in ok:
            raise AtlassianError(resp.status_code, describe(resp))
        return resp.json() if resp.content else None
