import base64

import httpx
import pytest
from github import GithubException

from src.core.config import Settings
from src.services.github.client import (
    GitHubContentSource,
    PyGithubContentSource,
    parse_github_repo,
    resolve_upstream_repo,
)
from tests.conftest import FakeContentSource


@pytest.mark.parametrize(
    "url,expected",
    [("https://github.com/psf/requests", "psf/requests"), ("https://github.com/psf/requests.git", "psf/requests"),
     ("git+https://github.com/psf/requests.git#egg=x", "psf/requests"), ("git@github.com:org/repo.git", "org/repo"),
     ("https://github.com/org/repo/tree/main", "org/repo"), ("https://gitlab.com/a/b", None), (None, None), ("", None)],
)  # fmt: skip
def test_parse_github_repo(url, expected):
    assert parse_github_repo(url) == expected


def test_fake_satisfies_protocol():
    assert isinstance(FakeContentSource(), GitHubContentSource)


def http(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_resolve_upstream_pip_from_project_urls():
    def handler(request):
        assert request.url.path == "/pypi/requests/json"
        return httpx.Response(200, json={"info": {"project_urls": {"Source": "https://github.com/psf/requests"}, "home_page": None}})

    assert await resolve_upstream_repo("pip", "requests", http(handler)) == "psf/requests"


async def test_resolve_upstream_npm_and_go():
    npm = http(lambda r: httpx.Response(200, json={"repository": {"url": "git+https://github.com/lodash/lodash.git"}}))
    assert await resolve_upstream_repo("npm", "lodash", npm) == "lodash/lodash"
    assert await resolve_upstream_repo("go", "github.com/opencontainers/runc", http(lambda r: httpx.Response(500))) == "opencontainers/runc"
    assert await resolve_upstream_repo("go", "golang.org/x/net", http(lambda r: httpx.Response(500))) is None
    assert await resolve_upstream_repo("maven", "a:b", http(lambda r: httpx.Response(500))) is None


async def test_resolve_upstream_swallows_http_errors():
    assert await resolve_upstream_repo("pip", "nope", http(lambda r: httpx.Response(404))) is None


class _Content:
    def __init__(self, text: str):
        self.decoded_content = text.encode()


class _Repo:
    def __init__(self, files=None, releases=None):
        self.files, self.releases = files or {}, releases or {}

    def get_contents(self, path, ref=None):
        if path == "dir":
            return [_Content("x")]
        if path not in self.files:
            raise GithubException(404, {"message": "Not Found"}, {})
        return _Content(self.files[path])

    def get_release(self, tag):
        if tag not in self.releases:
            raise GithubException(404, {"message": "Not Found"}, {})
        return type("R", (), {"body": self.releases[tag]})()


class _Item:
    def __init__(self, path):
        self.path = path


class _Gh:
    def __init__(self, repos, hits=()):
        self.repos, self.hits, self.queries = repos, hits, []

    def get_repo(self, name):
        return self.repos[name]

    def search_code(self, q):
        self.queries.append(q)
        return [_Item(p) for p in self.hits]


def source(gh, http_client=None):
    return PyGithubContentSource(Settings(_env_file=None), gh=gh, http=http_client or http(lambda r: httpx.Response(404)))


async def test_get_file_returns_text_none_for_missing_or_directory():
    s = source(_Gh({"org/r": _Repo(files={"a.txt": "hello"})}))
    assert await s.get_file("org/r", "a.txt") == "hello"
    assert await s.get_file("org/r", "missing") is None
    assert await s.get_file("org/r", "dir") is None


async def test_search_code_scopes_query_and_limits():
    gh = _Gh({}, hits=["a.py", "b.py", "c.py"])
    assert await source(gh).search_code("org/r", "requests", language="python", limit=2) == ["a.py", "b.py"]
    assert gh.queries == ["requests repo:org/r language:python"]


async def test_release_notes_tries_v_prefixed_then_bare_tag():
    gh = _Gh({"psf/requests": _Repo(releases={"2.32.0": "bare tag notes"})})
    pypi = http(lambda r: httpx.Response(200, json={"info": {"project_urls": {"Source": "https://github.com/psf/requests"}}}))
    assert await source(gh, pypi).get_release_notes("requests", "pip", "2.32.0") == "bare tag notes"
    gh = _Gh({"psf/requests": _Repo(releases={"v2.32.0": "v tag notes"})})
    assert await source(gh, pypi).get_release_notes("requests", "pip", "2.32.0") == "v tag notes"
    assert await source(_Gh({"psf/requests": _Repo()}), pypi).get_release_notes("requests", "pip", "9.9") is None


async def test_release_notes_none_when_upstream_unknown():
    assert await source(_Gh({})).get_release_notes("mystery", "pip", "1.0") is None


async def test_server_errors_are_retried(monkeypatch):
    from src.utils import retry as retry_mod

    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)
    calls = {"n": 0}

    class Flaky(_Repo):
        def get_contents(self, path, ref=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise GithubException(502, {}, {})
            return _Content("ok")

    assert await source(_Gh({"o/r": Flaky()})).get_file("o/r", "f") == "ok" and calls["n"] == 3


async def test_non_retryable_errors_propagate(monkeypatch):
    class Denied(_Repo):
        def get_contents(self, path, ref=None):
            raise GithubException(403, {"message": "forbidden"}, {})

    with pytest.raises(GithubException):
        await source(_Gh({"o/r": Denied()})).get_file("o/r", "f")
