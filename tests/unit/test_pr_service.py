"""PyGithubPullRequestService against fake PyGithub objects (no network)."""

import pytest
from github import GithubException

from src.agent.state import FileChange
from src.core.config import Settings
from src.services.github.pr_creator import PRConflictError, PyGithubPullRequestService, apply_changes
from src.utils import retry as retry_mod

REQS = "flask==3.0.0\nrequests==2.31.0\n"


def change(path="requirements.txt", orig="requests==2.31.0", new="requests==2.32.0"):
    return FileChange(file_path=path, original_content=orig, new_content=new, change_description="bump")


def gh_error(status):
    return GithubException(status, {"message": "x"}, {})


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


# --------------------------------------------------------------------------- apply_changes
def test_apply_changes_replaces_once_and_leaves_other_files():
    out = apply_changes({"requirements.txt": REQS, "x": "y"}, [change()])
    assert out == {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n", "x": "y"}


@pytest.mark.parametrize("content,msg", [("flask==3.0.0\n", "found 0"), ("requests==2.31.0\nrequests==2.31.0\n", "found 2")])
def test_apply_changes_conflicts(content, msg):
    with pytest.raises(PRConflictError, match=msg):
        apply_changes({"requirements.txt": content}, [change()])


def test_apply_changes_missing_file():
    with pytest.raises(PRConflictError, match="no longer exists"):
        apply_changes({}, [change()])


# --------------------------------------------------------------------------- fakes
class Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeRepo:
    def __init__(self, files=None, existing_refs=(), labels=("security",), pr_error=None, review_errors=(), label_create_error=False):
        self.default_branch = "main"
        self.files = files if files is not None else {"requirements.txt": REQS, "run.sh": "#!/bin/sh\n"}
        self.refs = set(existing_refs)
        self.labels = set(labels)
        self.pr_error, self.review_errors, self.label_create_error = pr_error, set(review_errors), label_create_error
        self.tree_elements: list[dict] = []
        self.commit_args: tuple | None = None
        self.deleted_refs: list[str] = []
        self.created_labels: list[str] = []
        self.pr = None
        self.requests: list[dict] = []
        self.applied_labels: list[str] = []
        self.pulls: list = []
        self.contents_refs: list = []
        self.protected, self.code_owner_reviews = True, True
        self.admins: list[str] = ["root"]
        self.codeowners: str | None = None

    def get_branch(self, name):
        repo = self
        return Obj(commit=Obj(sha="basesha"), protected=self.protected,
                   get_required_pull_request_reviews=lambda: Obj(require_code_owner_reviews=repo.code_owner_reviews))  # fmt: skip

    def get_contents(self, path, ref=None):
        self.contents_refs.append((path, ref))
        if path in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
            if self.codeowners is None or path != ".github/CODEOWNERS":
                raise gh_error(404)
            return Obj(decoded_content=self.codeowners.encode())
        if path not in self.files:
            raise gh_error(404)
        return Obj(decoded_content=self.files[path].encode())

    def get_git_commit(self, sha):
        return Obj(sha=sha)

    def get_git_tree(self, sha, recursive=False):
        return Obj(tree=[Obj(path="run.sh", mode="100755", type="blob"), Obj(path="requirements.txt", mode="100644", type="blob")])

    def create_git_tree(self, elements, base_tree=None):
        self.tree_elements = [e._identity for e in elements]
        return Obj(sha="treesha")

    def create_git_commit(self, message, tree, parents):
        self.commit_args = (message, tree.sha, [p.sha for p in parents])
        return Obj(sha="commitsha")

    def create_git_ref(self, ref, sha):
        if ref in self.refs:
            raise gh_error(422)
        self.refs.add(ref)

    def get_git_ref(self, ref):
        repo = self
        return Obj(delete=lambda: repo.deleted_refs.append(ref))

    def create_pull(self, title, body, head, base):
        if self.pr_error:
            raise self.pr_error
        repo = self
        self.pr = Obj(html_url="https://github.com/o/r/pull/9", number=9, head=Obj(ref=head), title=title, body=body)

        def review(reviewers=None, team_reviewers=None):
            who = (reviewers or team_reviewers)[0]
            if who in repo.review_errors:
                raise gh_error(422)
            repo.requests.append({"reviewers": reviewers, "teams": team_reviewers})

        self.pr.create_review_request = review
        self.pr.add_to_labels = lambda *names: repo.applied_labels.extend(names)
        return self.pr

    def get_label(self, name):
        if name not in self.labels:
            raise gh_error(404)

    def create_label(self, name, color):
        if self.label_create_error:
            raise gh_error(403)
        self.created_labels.append(name)

    def get_pulls(self, state, sort, direction):
        return self.pulls

    def get_collaborators(self, permission):
        return [Obj(login=a) for a in self.admins]


class FakeGh:
    def __init__(self, repo):
        self.repo = repo

    def get_repo(self, name):
        return self.repo


def service(repo):
    return PyGithubPullRequestService(Settings(_env_file=None), gh=FakeGh(repo))


async def create(repo, **kw):
    args = dict(repo="o/r", branch="fix/cve-X-r-20261009", title="t", body="b", commit_message="m", changes=[change()],
                labels=["security", "severity:high"], users=["alice"], teams=["org/platform"])  # fmt: skip
    return await service(repo).create_pr(**(args | kw))


# --------------------------------------------------------------------------- create_pr
async def test_single_atomic_commit_with_patched_content_and_preserved_modes():
    repo = FakeRepo()
    res = await create(repo, changes=[change(), change("run.sh", "#!/bin/sh\n", "#!/bin/sh\necho hi\n")])
    assert repo.contents_refs == [("requirements.txt", "basesha"), ("run.sh", "basesha")]  # read at the base commit
    assert repo.tree_elements == [
        {"path": "requirements.txt", "mode": "100644", "type": "blob", "content": "flask==3.0.0\nrequests==2.32.0\n"},
        {"path": "run.sh", "mode": "100755", "type": "blob", "content": "#!/bin/sh\necho hi\n"},
    ]  # fmt: skip
    assert repo.commit_args == ("m", "treesha", ["basesha"])
    assert "refs/heads/fix/cve-X-r-20261009" in repo.refs
    assert (res.url, res.number, res.branch, res.base_branch) == ("https://github.com/o/r/pull/9", 9, "fix/cve-X-r-20261009", "main")


async def test_labels_created_when_missing_and_reviewers_requested():
    repo = FakeRepo()
    res = await create(repo)
    assert repo.created_labels == ["severity:high"]  # 'security' already existed
    assert repo.applied_labels == ["security", "severity:high"] and res.labels == ["security", "severity:high"]
    assert repo.requests == [{"reviewers": ["alice"], "teams": None}, {"reviewers": None, "teams": ["platform"]}]
    assert res.reviewers == ["@alice", "@org/platform"] and res.warnings == []


async def test_invalid_reviewer_is_a_warning_not_a_failure():
    repo = FakeRepo(review_errors={"alice"})
    res = await create(repo)
    assert res.reviewers == ["@org/platform"] and any("@alice" in w for w in res.warnings)


async def test_label_permission_problems_are_warnings():
    repo = FakeRepo(labels=(), label_create_error=True)
    res = await create(repo)
    assert res.labels == [] and len(res.warnings) == 2 and res.url


async def test_taken_branch_name_gets_a_suffix():
    repo = FakeRepo(existing_refs={"refs/heads/fix/cve-X-r-20261009"})
    assert (await create(repo)).branch == "fix/cve-X-r-20261009-2"


async def test_all_branch_names_taken():
    taken = {"refs/heads/fix/cve-X-r-20261009"} | {f"refs/heads/fix/cve-X-r-20261009-{i}" for i in range(2, 6)}
    with pytest.raises(PRConflictError, match="free branch name"):
        await create(FakeRepo(existing_refs=taken))


async def test_failed_pr_creation_deletes_the_pushed_branch():
    repo = FakeRepo(pr_error=gh_error(422))
    with pytest.raises(GithubException):
        await create(repo)
    assert repo.deleted_refs == ["heads/fix/cve-X-r-20261009"]


async def test_base_branch_changed_since_validation():
    with pytest.raises(PRConflictError, match="found 0"):
        await create(FakeRepo(files={"requirements.txt": "requests==2.30.0\n"}))
    with pytest.raises(PRConflictError, match="no longer exists"):
        await create(FakeRepo(files={}))
    repo = FakeRepo(files={"requirements.txt": "requests==2.30.0\n"})
    with pytest.raises(PRConflictError):
        await create(repo)
    assert repo.refs == set()  # nothing pushed


async def test_transient_github_errors_are_retried():
    repo = FakeRepo()
    calls = {"n": 0}
    orig = repo.get_branch

    def flaky(name):
        calls["n"] += 1
        if calls["n"] < 3:
            raise gh_error(502)
        return orig(name)

    repo.get_branch = flaky
    assert (await create(repo)).number == 9 and calls["n"] == 3


# --------------------------------------------------------------------------- reads
async def test_find_open_pr_matches_prefix_and_extracts_job():
    repo = FakeRepo()
    marker = "text <!-- cve-remediation-bot job_id=abc-123 cve=CVE-2024-1 -->"
    repo.pulls = [
        Obj(head=Obj(ref="feature/x"), html_url="u0", number=1, body=""),
        Obj(head=Obj(ref="fix/cve-CVE-2024-2-r-20260101"), html_url="u1", number=2, body=marker),  # other CVE
        Obj(head=Obj(ref="fix/cve-CVE-2024-1-r-20260101"), html_url="u2", number=3, body=marker),
    ]
    found = await service(repo).find_open_pr("o/r", "CVE-2024-1", "fix/cve-")
    assert (found.number, found.job_id, found.branch) == (3, "abc-123", "fix/cve-CVE-2024-1-r-20260101")
    assert await service(repo).find_open_pr("o/r", "CVE-2099-9", "fix/cve-") is None


async def test_prefix_must_include_the_dash_so_cve_ids_do_not_collide():
    repo = FakeRepo()
    repo.pulls = [Obj(head=Obj(ref="fix/cve-CVE-2024-10-r-1"), html_url="u", number=1, body="")]
    assert await service(repo).find_open_pr("o/r", "CVE-2024-1", "fix/cve-") is None


async def test_code_owners_from_file_then_admin_fallback():
    repo = FakeRepo()
    repo.codeowners = "* @default\n/requirements*.txt @py-team\n"
    assert await service(repo).get_code_owners("o/r", ["requirements.txt"]) == ["@py-team"]
    repo.codeowners = "docs/ @docs\n"  # file exists but nothing matches -> admins
    assert await service(repo).get_code_owners("o/r", ["requirements.txt"]) == ["@root"]
    repo.codeowners = None  # no CODEOWNERS at all -> admins
    assert await service(repo).get_code_owners("o/r", ["requirements.txt"]) == ["@root"]


async def test_admin_fallback_failure_returns_nobody():
    repo = FakeRepo()
    repo.get_collaborators = lambda permission: (_ for _ in ()).throw(gh_error(403))
    assert await service(repo).get_code_owners("o/r", ["x"]) == []


async def test_branch_protection_summary_and_unknowns():
    repo = FakeRepo()
    assert await service(repo).branch_protection("o/r") == {"branch": "main", "protected": True, "code_owner_reviews_required": True}
    repo.protected = False
    assert (await service(repo).branch_protection("o/r"))["protected"] is False
    repo.get_branch = lambda name: (_ for _ in ()).throw(gh_error(403))
    assert (await service(repo).branch_protection("o/r"))["protected"] is None
