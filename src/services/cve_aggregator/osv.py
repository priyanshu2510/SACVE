"""OSV.dev API client."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx
import structlog

from src.core.config import Settings, settings as default_settings
from src.utils.retry import retry_async

log = structlog.get_logger(__name__)

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class OSVError(RuntimeError):
    """Raised on non-retryable OSV failures."""


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRYABLE_STATUS
    return isinstance(exc, httpx.TransportError)


class OSVClient:
    """Async client for ``api.osv.dev``."""

    def __init__(self, cfg: Settings | None = None, *, client: httpx.AsyncClient | None = None) -> None:
        self._cfg = cfg or default_settings
        self._client = client or httpx.AsyncClient(timeout=self._cfg.CVE_HTTP_TIMEOUT_SECONDS)
        self._owns_client = client is None
        self._base = self._cfg.OSV_API_BASE_URL.rstrip("/")

    async def aclose(self) -> None:
        """Close the underlying HTTP client if this instance created it."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> OSVClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    @retry_async(max_retries=3, base_delay=1.0, retry_on=(httpx.HTTPError,), is_retryable=_is_retryable)
    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        resp = await self._client.request(method, f"{self._base}{path}", **kwargs)
        if resp.status_code == 404:
            return resp
        resp.raise_for_status()
        return resp

    async def get_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        """``GET /v1/vulns/{id}``; accepts OSV ids (GHSA-…, PYSEC-…) and returns ``None`` on 404."""
        try:
            resp = await self._request("GET", f"/v1/vulns/{quote(vuln_id, safe='')}")
        except httpx.HTTPStatusError as exc:
            log.error("osv.get_vuln_failed", vuln_id=vuln_id, status=exc.response.status_code)
            raise OSVError(f"OSV returned {exc.response.status_code} for {vuln_id}") from exc
        return None if resp.status_code == 404 else resp.json()

    async def query_package(
        self, ecosystem: str, name: str, version: str | None = None
    ) -> list[dict[str, Any]]:
        """``POST /v1/query`` for a package (optionally at a version), following pagination."""
        body: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name}}
        if version:
            body["version"] = version
        vulns: list[dict[str, Any]] = []
        while True:
            try:
                resp = await self._request("POST", "/v1/query", json=body)
            except httpx.HTTPStatusError as exc:
                log.error("osv.query_failed", package=name, status=exc.response.status_code)
                raise OSVError(f"OSV returned {exc.response.status_code} for {name}") from exc
            data = resp.json()
            vulns.extend(data.get("vulns", []))
            token = data.get("next_page_token")
            if not token:
                return vulns
            body["page_token"] = token
