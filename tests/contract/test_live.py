"""Provider verification against the REAL services. Opt in with ``CONTRACT_LIVE=1``; tests needing credentials skip without them.

Everything here is read-only (no PRs, tickets, pages or notifications are created). Run before a release, and on a schedule, to
catch an upstream API change before production does.

    CONTRACT_LIVE=1 pytest tests/contract/test_live.py -v
    # plus, for the private integrations:
    CONTRACT_GITHUB_REPO=org/repo  (GITHUB_TOKEN)         CONTRACT_LIVE_LLM=1 (LLM_* settings)
    (JIRA_API_TOKEN / CONFLUENCE_API_TOKEN and the JIRA_* / CONFLUENCE_* settings)
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from src.core.config import settings
from src.services.cve_aggregator.normaliser import normalise_nvd, normalise_osv
from src.services.cve_aggregator.nvd import NVDClient
from src.services.cve_aggregator.osv import OSVClient
from src.services.cve_aggregator.service import CVEAggregator
from src.services.github.client import resolve_upstream_repo
from src.services.triage.prioritiser import JIRA_PRIORITY
from tests.contract import schemas as S

pytestmark = [
    pytest.mark.contract_live,
    pytest.mark.skipif(os.environ.get("CONTRACT_LIVE") != "1", reason="set CONTRACT_LIVE=1 to verify against the real services"),
]


# ------------------------------------------------------------------ public feeds (no credentials)
async def test_nvd_response_still_parses():
    async with NVDClient() as nvd:
        raw = await nvd.get_cve("CVE-2024-21626")
    assert raw is not None
    rec = normalise_nvd(raw)
    assert rec.cve_id == "CVE-2024-21626" and rec.cvss_v3_score and 0 < rec.cvss_v3_score <= 10 and rec.severity in {"HIGH", "CRITICAL"}
    assert rec.description and rec.cvss_v3_vector.startswith("CVSS:3") and rec.published_at.year == 2024


async def test_nvd_modified_window_is_accepted():
    """The exact date format and paging fields our incremental sync relies on."""
    from datetime import datetime, timedelta, timezone

    end = datetime.now(timezone.utc)
    async with NVDClient() as nvd:
        count = 0
        async for vuln in nvd.iter_modified(end - timedelta(minutes=30), end):
            assert "cve" in vuln and vuln["cve"]["id"].startswith("CVE-")
            count += 1
            if count >= 3:
                break


async def test_osv_advisory_and_package_query_still_parse():
    async with OSVClient() as osv:
        ghsa = await osv.get_vuln("GHSA-xr7r-f8xq-vfvv")
        vulns = await osv.query_package("PyPI", "requests", "2.31.0")
    rec = normalise_osv(ghsa)
    (pkg,) = [p for p in rec.affected_packages if p.package_name == "github.com/opencontainers/runc"]
    assert pkg.ecosystem.value == "go" and pkg.fixed_version == "1.1.12"
    assert any("CVE-2024-35195" in v.get("aliases", []) for v in vulns)  # requests 2.31.0 is affected by this one


async def test_aggregator_end_to_end_on_a_known_cve():
    async with NVDClient() as nvd, OSVClient() as osv:
        rec = await CVEAggregator(nvd, osv).fetch("CVE-2024-21626")
    assert rec.source == "NVD+OSV" and rec.cvss_v3_score == pytest.approx(8.6, abs=0.5)
    assert {(p.ecosystem.value, p.package_name, p.fixed_version) for p in rec.affected_packages} >= {("go", "github.com/opencontainers/runc", "1.1.12")}


async def test_registries_resolve_upstream_repositories():
    async with httpx.AsyncClient(timeout=20) as http:
        assert await resolve_upstream_repo("pip", "requests", http) == "psf/requests"
        assert await resolve_upstream_repo("npm", "lodash", http) == "lodash/lodash"
        assert await resolve_upstream_repo("go", "github.com/opencontainers/runc", http) == "opencontainers/runc"


# ------------------------------------------------------------------ GitHub (token + a repository to read)
@pytest.fixture
def github_repo():
    repo = os.environ.get("CONTRACT_GITHUB_REPO")
    if not (repo and settings.GITHUB_TOKEN):
        pytest.skip("set GITHUB_TOKEN and CONTRACT_GITHUB_REPO=org/repo")
    return repo


async def test_github_read_paths(github_repo):
    from src.services.github.client import PyGithubContentSource
    from src.services.github.pr_creator import PyGithubPullRequestService

    src, prs = PyGithubContentSource(), PyGithubPullRequestService()
    assert await src.get_file(github_repo, "README.md") is not None or await src.get_file(github_repo, "readme.md") is not None
    assert isinstance(await src.search_code(github_repo, "import", limit=3), list)
    assert isinstance(await prs.get_code_owners(github_repo, ["README.md"]), list)
    assert await prs.find_open_pr(github_repo, "CVE-1999-0000", settings.PR_BRANCH_PREFIX) is None
    protection = await prs.branch_protection(github_repo)
    assert set(protection) >= {"protected", "code_owner_reviews_required"}


# ------------------------------------------------------------------ Atlassian (tokens + settings)
@pytest.fixture
def jira_client():
    if not settings.JIRA_API_TOKEN:
        pytest.skip("JIRA_API_TOKEN not configured")
    from src.services.atlassian import AtlassianClient

    return AtlassianClient(settings.JIRA_BASE_URL, settings.JIRA_USER, settings.JIRA_API_TOKEN.get_secret_value())


async def test_jira_configuration_matches_the_real_instance(jira_client):
    me = await jira_client.request("GET", "/rest/api/3/myself")
    assert me["accountId"]
    names = {p["name"] for p in await jira_client.request("GET", "/rest/api/3/priority")}
    missing = set(JIRA_PRIORITY.values()) - names
    assert not missing, f"JIRA has no priority named {sorted(missing)} - tickets would be created without a priority (names found: {sorted(names)})"
    project = await jira_client.request("GET", f"/rest/api/3/project/{settings.JIRA_PROJECT_KEY}")
    assert settings.JIRA_ISSUE_TYPE in {t["name"] for t in project["issueTypes"]}, f"issue type {settings.JIRA_ISSUE_TYPE!r} does not exist in {settings.JIRA_PROJECT_KEY}"
    S.assert_valid(S.JIRA_SEARCH_RESPONSE, await jira_client.request("POST", "/rest/api/3/search/jql", json={"jql": f'project = "{settings.JIRA_PROJECT_KEY}"', "fields": ["key"], "maxResults": 1}))


async def test_confluence_space_and_parent_page_exist():
    if not settings.CONFLUENCE_API_TOKEN:
        pytest.skip("CONFLUENCE_API_TOKEN not configured")
    from src.services.atlassian import AtlassianClient

    wiki = AtlassianClient(settings.CONFLUENCE_BASE_URL, settings.CONFLUENCE_USER, settings.CONFLUENCE_API_TOKEN.get_secret_value())
    space = await wiki.request("GET", f"/wiki/rest/api/space/{settings.CONFLUENCE_SPACE_KEY}")
    assert space["key"] == settings.CONFLUENCE_SPACE_KEY
    parent = await wiki.request("GET", f"/wiki/rest/api/content/{settings.CONFLUENCE_PARENT_PAGE_ID}")
    assert parent["type"] == "page" and parent["space"]["key"] == settings.CONFLUENCE_SPACE_KEY


# ------------------------------------------------------------------ internal LLM
async def test_llm_json_mode_contract():
    if not (os.environ.get("CONTRACT_LIVE_LLM") == "1" and settings.LLM_API_KEY):
        pytest.skip("set CONTRACT_LIVE_LLM=1 and the LLM_* settings")
    from src.agent.nodes.fix_generator import LLMClient

    async with LLMClient() as client:
        text, usage = await client.complete([{"role": "system", "content": "Reply with a JSON object only."}, {"role": "user", "content": 'Return {"ok": true}'}])
    assert json.loads(text) is not None  # JSON mode really returns JSON
    S.assert_valid(S.LLM_RESPONSE, {"choices": [{"message": {"role": "assistant", "content": text}}], "usage": usage})
