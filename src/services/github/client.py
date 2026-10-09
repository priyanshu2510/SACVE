"""GitHub access used by the agent.

The agent depends on the :class:`GitHubContentSource` protocol. v1 ships a PyGithub
implementation; the locked design calls for a GitHub MCP adapter (fixed, deterministic call
sequences) behind this same protocol once ``create_pr`` is built.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Protocol, runtime_checkable

import httpx
import structlog
from github import Auth, Github, GithubException, RateLimitExceededException
from github.GithubRetry import GithubRetry

from src.core.config import Settings, secret_value, settings as default_settings
from src.utils.retry import retry_async

log = structlog.get_logger(__name__)

_GITHUB_URL = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$")


@runtime_checkable
class GitHubContentSource(Protocol):
    """Read-only repository content access needed by ``assemble_context``."""

    async def get_file(self, repo: str, path: str, ref: str | None = None) -> str | None:
        """Return the decoded text of ``path`` or ``None`` if it does not exist."""

    async def search_code(self, repo: str, query: str, language: str | None = None, limit: int = 10) -> list[str]:
        """Return paths in ``repo`` whose content matches ``query`` (best first)."""

    async def get_release_notes(self, package: str, ecosystem: str, version: str) -> str | None:
        """Return the upstream release notes / changelog entry for ``package`` at ``version``."""


def _retryable(exc: BaseException) -> bool:
    if isinstance(exc, RateLimitExceededException):
        return True
    return isinstance(exc, GithubException) and exc.status in (500, 502, 503, 504)


def parse_github_repo(url: str | None) -> str | None:
    """Extract ``owner/repo`` from a GitHub URL (``https://``, ``git+https://``, ``git@``)."""
    if not url:
        return None
    match = _GITHUB_URL.search(url.strip())
    return f"{match.group(1)}/{match.group(2)}" if match else None


async def resolve_upstream_repo(
    ecosystem: str, package: str, http: httpx.AsyncClient
) -> str | None:
    """Best-effort mapping of a package to its upstream GitHub ``owner/repo``."""
    try:
        if ecosystem == "go":
            return parse_github_repo(f"https://{package}") if package.startswith("github.com/") else None
        if ecosystem == "pip":
            resp = await http.get(f"https://pypi.org/pypi/{package}/json")
            resp.raise_for_status()
            info = resp.json()["info"]
            urls = [*(info.get("project_urls") or {}).values(), info.get("home_page")]
            return next((r for r in map(parse_github_repo, urls) if r), None)
        if ecosystem == "npm":
            resp = await http.get(f"https://registry.npmjs.org/{package}")
            resp.raise_for_status()
            repo = resp.json().get("repository")
            return parse_github_repo(repo.get("url") if isinstance(repo, dict) else repo)
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        log.warning("github.resolve_upstream_failed", ecosystem=ecosystem, package=package, error=str(exc))
    return None


class PyGithubBase:
    """Shared PyGithub plumbing: fine-grained-PAT client and a retrying thread-offloaded call helper."""

    def __init__(self, cfg: Settings | None = None, *, gh: Github | None = None) -> None:
        self._cfg = cfg or default_settings
        if gh is None:
            token = secret_value(self._cfg.GITHUB_TOKEN, "GITHUB_TOKEN")
            gh = Github(
                auth=Auth.Token(token),
                base_url=self._cfg.GITHUB_API_URL,
                retry=GithubRetry(total=3),
                seconds_between_requests=self._cfg.GITHUB_SECONDS_BETWEEN_REQUESTS,
                seconds_between_writes=self._cfg.GITHUB_SECONDS_BETWEEN_WRITES,
            )
        self._gh = gh

    @retry_async(max_retries=3, base_delay=2.0, retry_on=(GithubException,), is_retryable=_retryable)
    async def _call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Run blocking PyGithub code in a worker thread; rate limits and 5xx are retried with backoff."""
        return await asyncio.to_thread(fn, *args, **kwargs)


class PyGithubContentSource(PyGithubBase):
    """PyGithub-backed :class:`GitHubContentSource` (blocking calls run in worker threads)."""

    def __init__(self, cfg: Settings | None = None, *, gh: Github | None = None, http: httpx.AsyncClient | None = None):
        super().__init__(cfg, gh=gh)
        self._http = http or httpx.AsyncClient(timeout=self._cfg.CVE_HTTP_TIMEOUT_SECONDS)

    async def get_file(self, repo: str, path: str, ref: str | None = None) -> str | None:
        """Fetch a file's text; ``None`` for missing files or directories."""

        def _fetch() -> str | None:
            try:
                content = self._gh.get_repo(repo).get_contents(path, ref=ref) if ref else self._gh.get_repo(repo).get_contents(path)
            except GithubException as exc:
                if exc.status == 404:
                    return None
                raise
            if isinstance(content, list):
                return None
            return content.decoded_content.decode("utf-8", errors="replace")

        return await self._call(_fetch)

    async def search_code(self, repo: str, query: str, language: str | None = None, limit: int = 10) -> list[str]:
        """Code search scoped to one repo (GitHub caps this API at ~10 req/min; retries back off)."""
        q = f"{query} repo:{repo}" + (f" language:{language}" if language else "")

        def _search() -> list[str]:
            results = self._gh.search_code(q)
            return [item.path for item in results[:limit]]

        return await self._call(_search)

    async def get_release_notes(self, package: str, ecosystem: str, version: str) -> str | None:
        """Release notes for the safe version from the package's upstream GitHub repo, if resolvable."""
        upstream = await resolve_upstream_repo(ecosystem, package, self._http)
        if upstream is None:
            return None

        def _fetch() -> str | None:
            repo = self._gh.get_repo(upstream)
            for tag in (f"v{version}", version):
                try:
                    release = repo.get_release(tag)
                except GithubException as exc:
                    if exc.status == 404:
                        continue
                    raise
                return release.body or None
            return None

        return await self._call(_fetch)
