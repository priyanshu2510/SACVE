"""Pull-request creation behind a protocol (PyGithub today; a GitHub MCP adapter can implement it later)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import structlog
from github import GithubException, InputGitTreeElement

from src.agent.state import FileChange
from src.services.github.client import PyGithubBase
from src.services.github.codeowners import CODEOWNERS_LOCATIONS, CodeOwners
from src.services.github.pr_description import MARKER_RE

log = structlog.get_logger(__name__)

LABEL_COLORS = {"security": "b60205", "cve-fix": "d93f0b", "automated": "ededed"}
DEFAULT_LABEL_COLOR = "fbca04"
MAX_PRS_SCANNED = 200
MAX_BRANCH_ATTEMPTS = 5


class PRConflictError(RuntimeError):
    """The base branch no longer matches what the fix was validated against."""


@dataclass(frozen=True)
class ExistingPR:
    """An open bot PR for the same CVE."""

    url: str
    number: int
    branch: str
    job_id: str | None


@dataclass
class PRResult:
    """Outcome of :meth:`PullRequestService.create_pr`."""

    url: str
    number: int
    branch: str
    base_branch: str
    labels: list[str] = field(default_factory=list)
    reviewers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@runtime_checkable
class PullRequestService(Protocol):
    """GitHub operations needed by ``create_pr``."""

    async def find_open_pr(self, repo: str, cve_id: str, branch_prefix: str) -> ExistingPR | None:
        """Return an open bot PR for ``cve_id`` in ``repo`` (dedup guard), if any."""

    async def get_code_owners(self, repo: str, paths: list[str]) -> list[str]:
        """CODEOWNERS of ``paths``; falls back to repo admins when nothing matches."""

    async def branch_protection(self, repo: str) -> dict[str, Any]:
        """Default-branch protection summary: ``protected`` and ``code_owner_reviews_required``."""

    async def create_pr(
        self, *, repo: str, branch: str, title: str, body: str, commit_message: str,
        changes: list[FileChange], labels: list[str], users: list[str], teams: list[str],
    ) -> PRResult:  # fmt: skip
        """Commit ``changes`` to a new ``branch`` and open a PR against the default branch."""


def apply_changes(files: dict[str, str], changes: list[FileChange]) -> dict[str, str]:
    """Apply section replacements to the base-branch file contents.

    Raises :class:`PRConflictError` if a section is missing or ambiguous, i.e. the repository
    changed since the fix was validated in the sandbox.
    """
    out = dict(files)
    for change in changes:
        current = out.get(change.file_path)
        if current is None:
            raise PRConflictError(f"{change.file_path} no longer exists on the base branch")
        count = current.count(change.original_content)
        if count != 1:
            raise PRConflictError(
                f"{change.file_path}: expected exactly one match of the validated section on the base branch, found {count}"
            )
        out[change.file_path] = current.replace(change.original_content, change.new_content, 1)
    return out


class PyGithubPullRequestService(PyGithubBase):
    """PyGithub implementation. One commit via the Git Data API, so multi-file fixes are atomic."""

    # -- reads -------------------------------------------------------------------------------

    async def find_open_pr(self, repo: str, cve_id: str, branch_prefix: str) -> ExistingPR | None:
        """Scan open PRs for our branch prefix (and body marker) for ``cve_id``."""

        def _find() -> ExistingPR | None:
            prefix = f"{branch_prefix}{cve_id}-"
            for i, pr in enumerate(self._gh.get_repo(repo).get_pulls(state="open", sort="created", direction="desc")):
                if i >= MAX_PRS_SCANNED:
                    break
                if pr.head.ref.startswith(prefix):
                    m = MARKER_RE.search(pr.body or "")
                    return ExistingPR(pr.html_url, pr.number, pr.head.ref, m.group("job") if m else None)
            return None

        return await self._call(_find)

    async def get_code_owners(self, repo: str, paths: list[str]) -> list[str]:
        """Resolve owners from CODEOWNERS; fall back to the repository's admins."""

        def _owners() -> list[str]:
            r = self._gh.get_repo(repo)
            for location in CODEOWNERS_LOCATIONS:
                try:
                    text = r.get_contents(location).decoded_content.decode("utf-8", errors="replace")
                except GithubException as exc:
                    if exc.status == 404:
                        continue
                    raise
                owners = CodeOwners.parse(text).owners_for_paths(paths)
                if owners:
                    return owners
                break
            try:
                return [f"@{u.login}" for u in r.get_collaborators(permission="admin")[:3]]
            except GithubException as exc:
                log.warning("pr.admin_fallback_failed", repo=repo, status=exc.status)
                return []

        return await self._call(_owners)

    async def branch_protection(self, repo: str) -> dict[str, Any]:
        """Best effort: reading protection details needs admin rights, so unknowns are reported as ``None``."""

        def _check() -> dict[str, Any]:
            r = self._gh.get_repo(repo)
            branch = r.get_branch(r.default_branch)
            info: dict[str, Any] = {"branch": r.default_branch, "protected": bool(branch.protected), "code_owner_reviews_required": None}
            if branch.protected:
                try:
                    reviews = branch.get_required_pull_request_reviews()
                    info["code_owner_reviews_required"] = bool(reviews.require_code_owner_reviews)
                except GithubException:
                    pass
            return info

        try:
            return await self._call(_check)
        except GithubException as exc:
            return {"protected": None, "code_owner_reviews_required": None, "error": f"HTTP {exc.status}"}

    # -- write -------------------------------------------------------------------------------

    async def create_pr(
        self, *, repo: str, branch: str, title: str, body: str, commit_message: str,
        changes: list[FileChange], labels: list[str], users: list[str], teams: list[str],
    ) -> PRResult:  # fmt: skip
        """Branch from the default branch head, commit once, open the PR, then label and request review."""

        def _create() -> PRResult:
            r = self._gh.get_repo(repo)
            base_name = r.default_branch
            base_sha = r.get_branch(base_name).commit.sha

            files: dict[str, str] = {}
            for path in dict.fromkeys(c.file_path for c in changes):
                try:
                    files[path] = r.get_contents(path, ref=base_sha).decoded_content.decode("utf-8")
                except GithubException as exc:
                    if exc.status == 404:
                        raise PRConflictError(f"{path} no longer exists on the base branch") from exc
                    raise
            patched = apply_changes(files, changes)

            base_commit = r.get_git_commit(base_sha)
            modes = {e.path: e.mode for e in r.get_git_tree(base_sha, recursive=True).tree if e.type == "blob"}
            elements = [
                InputGitTreeElement(path, modes.get(path, "100644"), "blob", content=content)
                for path, content in patched.items()
            ]
            commit = r.create_git_commit(commit_message, r.create_git_tree(elements, base_tree=r.get_git_tree(base_sha)), [base_commit])

            name = branch
            for attempt in range(MAX_BRANCH_ATTEMPTS):
                name = branch if attempt == 0 else f"{branch}-{attempt + 1}"
                try:
                    r.create_git_ref(f"refs/heads/{name}", commit.sha)
                    break
                except GithubException as exc:
                    if exc.status != 422:  # 422 = ref already exists
                        raise
            else:
                raise PRConflictError(f"could not find a free branch name starting with {branch}")

            try:
                pr = r.create_pull(title=title, body=body, head=name, base=base_name)
            except Exception:
                try:
                    r.get_git_ref(f"heads/{name}").delete()  # do not leave an orphan branch behind
                except GithubException:
                    log.warning("pr.orphan_branch_cleanup_failed", repo=repo, branch=name)
                raise

            result = PRResult(pr.html_url, pr.number, name, base_name)
            self._label(r, pr, labels, result)
            self._request_review(pr, users, teams, result)
            return result

        return await self._call(_create)

    @staticmethod
    def _label(repo: Any, pr: Any, labels: list[str], result: PRResult) -> None:
        for label in labels:
            try:
                repo.get_label(label)
            except GithubException as exc:
                if exc.status != 404:
                    result.warnings.append(f"could not check label {label!r}: HTTP {exc.status}")
                    continue
                try:
                    repo.create_label(label, LABEL_COLORS.get(label, DEFAULT_LABEL_COLOR))
                except GithubException as create_exc:
                    result.warnings.append(f"could not create label {label!r}: HTTP {create_exc.status}")
                    continue
            result.labels.append(label)
        try:
            if result.labels:
                pr.add_to_labels(*result.labels)
        except GithubException as exc:
            result.warnings.append(f"could not apply labels: HTTP {exc.status}")
            result.labels = []

    @staticmethod
    def _request_review(pr: Any, users: list[str], teams: list[str], result: PRResult) -> None:
        """Request reviewers one by one so a single invalid owner does not drop the rest."""
        for user in users:
            try:
                pr.create_review_request(reviewers=[user])
                result.reviewers.append(f"@{user}")
            except GithubException as exc:
                result.warnings.append(f"could not request review from @{user}: HTTP {exc.status}")
        for team in teams:
            try:
                pr.create_review_request(team_reviewers=[team.split("/", 1)[-1]])
                result.reviewers.append(f"@{team}")
            except GithubException as exc:
                result.warnings.append(f"could not request review from @{team}: HTTP {exc.status}")
