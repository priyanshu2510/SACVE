"""PyGithub -> HTTP -> (fake) GitHub: validate the real wire format our GitHub code produces."""

from __future__ import annotations

import pytest

from src.agent.state import FileChange
from src.core.config import Settings
from src.services.github.client import PyGithubContentSource
from src.services.github.pr_creator import PRConflictError, PyGithubPullRequestService
from src.services.github.repos import PyGithubRepoLister
from src.utils import retry as retry_mod
from tests.contract import schemas as S
from tests.contract.fake_github import BASE_SHA, COMMIT_SHA, TREE_SHA, FakeGitHub, FakeGitHubState


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


@pytest.fixture
def gh():
    server = FakeGitHub(FakeGitHubState()).start()
    yield server
    server.stop()


def cfg(gh: FakeGitHub) -> Settings:
    return Settings(_env_file=None, GITHUB_API_URL=gh.url, GITHUB_TOKEN="ghp_contract_token",
                    GITHUB_SECONDS_BETWEEN_REQUESTS=0, GITHUB_SECONDS_BETWEEN_WRITES=0)  # the fake server needs no pacing


def bump(path="requirements.txt", old="requests==2.31.0", new="requests==2.32.0") -> FileChange:
    return FileChange(file_path=path, original_content=old, new_content=new, change_description="bump")


async def create(gh: FakeGitHub, **kw):
    svc = PyGithubPullRequestService(cfg(gh))
    args = dict(repo="o/r", branch="fix/cve-CVE-2024-35195-r-20261009", title="fix(medium): CVE-2024-35195 bump requests", body="## body\n<!-- marker -->",
                commit_message="fix(CVE-2024-35195): bump requests\n\nAutomated.", changes=[bump()], labels=["security", "cve-fix", "severity:medium"],
                users=["alice"], teams=["org/platform"])  # fmt: skip
    return await svc.create_pr(**(args | kw))


# ------------------------------------------------------------------ the PR flow on the wire
async def test_pull_request_flow_uses_valid_github_requests(gh):
    result = await create(gh)
    s = gh.state
    (tree,) = s.find("POST", "/git/trees")
    (commit,) = s.find("POST", "/git/commits")
    (ref,) = s.find("POST", "/git/refs")
    (pull,) = s.find("POST", "/pulls")
    S.assert_valid(S.GH_CREATE_TREE, tree.body)
    S.assert_valid(S.GH_CREATE_COMMIT, commit.body)
    S.assert_valid(S.GH_CREATE_REF, ref.body)
    S.assert_valid(S.GH_CREATE_PULL, pull.body)
    # one atomic commit, parented on the default branch head, containing exactly the patched file
    assert tree.body["base_tree"] == BASE_SHA and [e["path"] for e in tree.body["tree"]] == ["requirements.txt"]
    assert tree.body["tree"][0]["content"] == "flask==3.0.0\nrequests==2.32.0\n" and tree.body["tree"][0]["mode"] == "100644"
    assert commit.body["tree"] == TREE_SHA and commit.body["parents"] == [BASE_SHA]
    assert ref.body == {"ref": "refs/heads/fix/cve-CVE-2024-35195-r-20261009", "sha": COMMIT_SHA}
    assert pull.body["head"] == "fix/cve-CVE-2024-35195-r-20261009" and pull.body["base"] == "main" and "<!-- marker -->" in pull.body["body"]
    assert (result.url, result.number) == ("https://github.com/o/r/pull/1", 1)


async def test_labels_and_reviewers_are_valid_requests(gh):
    result = await create(gh)
    s = gh.state
    for rec in s.find("POST", "/issues/1/labels"):
        S.assert_valid(S.GH_ADD_LABELS, rec.body)
    for rec in [r for r in s.requests if r.method == "POST" and r.path == "/repos/o/r/labels"]:
        S.assert_valid(S.GH_CREATE_LABEL, rec.body)
    reviews = [r.body for r in s.find("POST", "/requested_reviewers")]
    assert reviews == [{"reviewers": ["alice"]}, {"team_reviewers": ["platform"]}]  # team slug only, never org/slug
    for body in reviews:
        S.assert_valid(S.GH_REVIEW_REQUEST, body)
    created = sorted(r.body["name"] for r in s.requests if r.method == "POST" and r.path == "/repos/o/r/labels")
    assert created == ["cve-fix", "severity:medium"]  # 'security' already existed, so it is not re-created
    assert result.labels == ["security", "cve-fix", "severity:medium"] and result.reviewers == ["@alice", "@org/platform"]


async def test_executable_bit_survives_the_commit(gh):
    await create(gh, changes=[bump("run.sh", "#!/bin/sh", "#!/bin/sh\necho patched")])
    (tree,) = gh.state.find("POST", "/git/trees")
    assert tree.body["tree"][0] == {"path": "run.sh", "mode": "100755", "type": "blob", "content": "#!/bin/sh\necho patched\n"}
    S.assert_valid(S.GH_CREATE_TREE, tree.body)


async def test_auth_and_api_version_headers(gh):
    await create(gh)
    headers = gh.state.requests[0].headers
    assert "ghp_contract_token" in headers["authorization"] and headers["authorization"].split()[0] in ("token", "Bearer")
    assert headers["accept"].startswith("application/vnd.github") or headers["accept"] == "*/*"


async def test_the_base_commit_is_read_before_anything_is_written(gh):
    await create(gh)
    paths = [(r.method, r.path.replace("/repos/o/r", "")) for r in gh.state.requests]
    first_write = next(i for i, (m, _) in enumerate(paths) if m == "POST")
    reads = paths[:first_write]
    assert ("GET", "/branches/main") in reads and ("GET", "/contents/requirements.txt") in reads
    contents = next(r for r in gh.state.requests if r.path.endswith("/contents/requirements.txt"))
    assert contents.query["ref"] == [BASE_SHA]  # patched content comes from the exact commit we branch from


# ------------------------------------------------------------------ error handling on the wire
async def test_taken_branch_name_is_retried_with_a_suffix(gh):
    gh.state.refs.add("refs/heads/fix/cve-CVE-2024-35195-r-20261009")
    result = await create(gh)
    assert result.branch == "fix/cve-CVE-2024-35195-r-20261009-2"
    assert [r.body["ref"] for r in gh.state.find("POST", "/git/refs")] == ["refs/heads/fix/cve-CVE-2024-35195-r-20261009", "refs/heads/fix/cve-CVE-2024-35195-r-20261009-2"]


async def test_failed_pull_request_deletes_the_branch_it_pushed(gh):
    gh.state.fail_pull_creation = True
    from github import GithubException

    with pytest.raises(GithubException):
        await create(gh)
    (delete,) = gh.state.find("DELETE", "/git/refs/heads/fix/cve-CVE-2024-35195-r-20261009")
    assert delete.method == "DELETE"


async def test_moved_base_branch_fails_before_anything_is_pushed(gh):
    gh.state.files["requirements.txt"] = "requests==2.30.0\n"  # someone changed the file after the sandbox validated it
    with pytest.raises(PRConflictError):
        await create(gh)
    assert not [r for r in gh.state.requests if r.method == "POST"]


async def test_transient_gateway_errors_are_retried(gh):
    gh.state.server_errors = 2
    result = await create(gh)
    assert result.number == 1


async def test_rate_limiting_is_retried(gh):
    gh.state.rate_limited = 1
    assert (await create(gh)).number == 1


# ------------------------------------------------------------------ reads
async def test_find_open_pr_reads_the_pull_list_and_marker(gh):
    await create(gh)
    gh.state.pulls[0]["body"] = "x <!-- cve-remediation-bot job_id=abc cve=CVE-2024-35195 -->"
    found = await PyGithubPullRequestService(cfg(gh)).find_open_pr("o/r", "CVE-2024-35195", "fix/cve-")
    assert found.number == 1 and found.job_id == "abc"
    req = gh.state.find("GET", "/repos/o/r/pulls")[-1]
    assert req.query["state"] == ["open"] and req.query["sort"] == ["created"] and req.query["direction"] == ["desc"]


async def test_code_owners_come_from_the_github_codeowners_file(gh):
    gh.state.codeowners = "* @default\n/requirements*.txt @py-team alice@co.com\n"
    svc = PyGithubPullRequestService(cfg(gh))
    assert await svc.get_code_owners("o/r", ["requirements.txt"]) == ["@py-team", "alice@co.com"]
    gh.state.codeowners = None
    assert await svc.get_code_owners("o/r", ["requirements.txt"]) == ["@root"]  # falls back to repo admins
    assert gh.state.find("GET", "/collaborators")[-1].query["permission"] == ["admin"]


async def test_branch_protection_summary(gh):
    svc = PyGithubPullRequestService(cfg(gh))
    assert await svc.branch_protection("o/r") == {"branch": "main", "protected": True, "code_owner_reviews_required": True}
    gh.state.protected = False
    assert (await svc.branch_protection("o/r"))["protected"] is False


async def test_content_source_requests(gh):
    src = PyGithubContentSource(cfg(gh))
    assert (await src.get_file("o/r", "requirements.txt")) == "flask==3.0.0\nrequests==2.31.0\n" and await src.get_file("o/r", "nope.txt") is None
    assert await src.search_code("o/r", "requests", language="python", limit=5) == ["app/client.py"]
    assert gh.state.find("GET", "/search/code")[0].query["q"] == ["requests repo:o/r language:python"]
    assert await src.get_release_notes("requests", "go", "2.32.0") is None  # no upstream resolvable for this ecosystem/package here


async def test_repo_listing_and_topics(gh):
    infos = await PyGithubRepoLister(cfg(gh)).list_repos("o")
    assert [(i.full_name, i.default_branch, i.archived) for i in infos] == [("o/r", "main", False)]
    assert infos[0].topics == ["python", "cve-exempt"]
    assert gh.state.find("GET", "/orgs/o/repos")[0].query["type"] == ["all"]
