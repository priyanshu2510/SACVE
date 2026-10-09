"""NVD CVE API 2.0 client."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
import structlog

from src.core.config import Settings, settings as default_settings
from src.utils.rate_limiter import RateLimiter
from src.utils.retry import retry_async

log = structlog.get_logger(__name__)

PAGE_SIZE = 2000
_RETRYABLE_STATUS = {403, 429, 500, 502, 503, 504}  # NVD signals throttling with 403


class NVDError(RuntimeError):
    """Raised on non-retryable NVD failures."""


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRYABLE_STATUS
    return isinstance(exc, httpx.TransportError)


class NVDClient:
    """Async client for ``services.nvd.nist.gov/rest/json/cves/2.0``.

    Rate limited to NVD's published limits: 5 requests / 30 s without an API key, 50 with one.
    """

    def __init__(
        self,
        cfg: Settings | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._cfg = cfg or default_settings
        key = self._cfg.NVD_API_KEY.get_secret_value() if self._cfg.NVD_API_KEY else None
        headers = {"apiKey": key} if key else {}
        self._client = client or httpx.AsyncClient(
            timeout=self._cfg.CVE_HTTP_TIMEOUT_SECONDS, headers=headers
        )
        self._owns_client = client is None
        self._limiter = rate_limiter or RateLimiter(50 if key else 5, 30.0)

    async def aclose(self) -> None:
        """Close the underlying HTTP client if this instance created it."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> NVDClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    @retry_async(max_retries=3, base_delay=2.0, retry_on=(httpx.HTTPError,), is_retryable=_is_retryable)
    async def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        await self._limiter.acquire()
        resp = await self._client.get(self._cfg.NVD_API_BASE_URL, params=params)
        resp.raise_for_status()
        return resp.json()

    async def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Return the raw ``vulnerabilities[]`` element for ``cve_id`` or ``None`` if NVD has none."""
        try:
            data = await self._get({"cveId": cve_id.upper()})
        except httpx.HTTPStatusError as exc:
            log.error("nvd.get_cve_failed", cve_id=cve_id, status=exc.response.status_code)
            raise NVDError(f"NVD returned {exc.response.status_code} for {cve_id}") from exc
        vulns = data.get("vulnerabilities", [])
        return vulns[0] if vulns else None

    async def iter_modified(self, start: datetime, end: datetime) -> AsyncIterator[dict[str, Any]]:
        """Yield every CVE modified in ``[start, end]`` (NVD caps the window at 120 days)."""
        if (end - start).days > 120:
            raise ValueError("NVD allows a maximum window of 120 days")
        params: dict[str, Any] = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": PAGE_SIZE,
            "startIndex": 0,
        }
        while True:
            try:
                data = await self._get(params)
            except httpx.HTTPStatusError as exc:
                log.error("nvd.page_failed", start_index=params["startIndex"], status=exc.response.status_code)
                raise NVDError(f"NVD returned {exc.response.status_code}") from exc
            for vuln in data.get("vulnerabilities", []):
                yield vuln
            fetched = data["startIndex"] + data["resultsPerPage"]
            if fetched >= data["totalResults"] or data["resultsPerPage"] == 0:
                return
            params["startIndex"] = fetched
