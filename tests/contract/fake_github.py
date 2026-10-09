"""A small HTTP server that speaks enough of the GitHub REST API for PyGithub, and records every request.

PyGithub is exercised for real (its own request building and response parsing); only the server is fake. That lets the
contract tests validate the *wire format* of what our services send - something mocks of PyGithub objects cannot do.
"""

from __future__ import annotations

import base64
import json
import re
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

BASE_SHA = "b" * 40
TREE_SHA = "c" * 40
COMMIT_SHA = "d" * 40


@dataclass
class Recorded:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: Any


@dataclass
class FakeGitHubState:
    files: dict[str, str] = field(default_factory=lambda: {"requirements.txt": "flask==3.0.0\nrequests==2.31.0\n", "run.sh": "#!/bin/sh\n"})
    modes: dict[str, str] = field(default_factory=lambda: {"requirements.txt": "100644", "run.sh": "100755"})
    labels: set[str] = field(default_factory=lambda: {"security"})
    refs: set[str] = field(default_factory=set)
    pulls: list[dict[str, Any]] = field(default_factory=list)
    codeowners: str | None = None
    admins: list[str] = field(default_factory=lambda: ["root"])
    protected: bool = True
    rate_limited: int = 0  # number of upcoming requests answered with a primary rate-limit 403
    server_errors: int = 0  # number of upcoming requests answered with a 502
    fail_pull_creation: bool = False
    requests: list[Recorded] = field(default_factory=list)

    def find(self, method: str, suffix: str) -> list[Recorded]:
        return [r for r in self.requests if r.method == method and r.path.endswith(suffix)]


def _user(login: str = "octo") -> dict[str, Any]:
    return {"login": login, "id": 1, "type": "User", "site_admin": False}


class FakeGitHub:
    """Start with ``FakeGitHub().start()``; ``.url`` is the API base URL to give PyGithub."""

    def __init__(self, state: FakeGitHubState | None = None) -> None:
        self.state = state or FakeGitHubState()
        self._server: ThreadingHTTPServer | None = None
        self.url = ""

    def start(self) -> FakeGitHub:
        state, routes = self.state, self._routes()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence
                pass

            def _handle(self) -> None:
                parsed = urlparse(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else None
                rec = Recorded(self.command, parsed.path, parse_qs(parsed.query), {k.lower(): v for k, v in self.headers.items()}, body)
                state.requests.append(rec)
                if state.rate_limited > 0:
                    state.rate_limited -= 1
                    return self._send(403, {"message": "API rate limit exceeded"}, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0", "Retry-After": "0"})
                if state.server_errors > 0:
                    state.server_errors -= 1
                    return self._send(502, {"message": "Bad Gateway"})
                for method, pattern, fn in routes:
                    m = re.fullmatch(pattern, parsed.path)
                    if method == self.command and m:
                        status, payload = fn(rec, *m.groups())
                        return self._send(status, payload)
                self._send(404, {"message": "Not Found"})

            def _send(self, status: int, payload: Any, extra: dict[str, str] | None = None) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    # ------------------------------------------------------------------ the API surface
    def _routes(self) -> list[tuple[str, str, Callable[..., tuple[int, Any]]]]:
        s, u = self.state, lambda: self.url  # noqa: E731
        repo = lambda: {  # noqa: E731
            "id": 7, "name": "r", "full_name": "o/r", "default_branch": "main", "private": True, "archived": False, "owner": _user("o"),
            "url": f"{u()}/repos/o/r", "html_url": "https://github.com/o/r", "topics": [],
        }  # fmt: skip

        def pr_json(number: int, ref: str, body: str = "", title: str = "t") -> dict[str, Any]:
            return {
                "url": f"{u()}/repos/o/r/pulls/{number}", "id": number, "number": number, "state": "open", "title": title, "body": body,
                "html_url": f"https://github.com/o/r/pull/{number}", "issue_url": f"{u()}/repos/o/r/issues/{number}", "user": _user(),
                "head": {"ref": ref, "sha": COMMIT_SHA, "label": f"o:{ref}", "user": _user("o"), "repo": repo()},
                "base": {"ref": "main", "sha": BASE_SHA, "label": "o:main", "user": _user("o"), "repo": repo()},
            }  # fmt: skip

        def get_contents(rec: Recorded, path: str) -> tuple[int, Any]:
            if path in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
                text = s.codeowners if path == ".github/CODEOWNERS" else None
            else:
                text = s.files.get(path)
            if text is None:
                return 404, {"message": "Not Found"}
            return 200, {"type": "file", "encoding": "base64", "name": path.split("/")[-1], "path": path, "sha": "e" * 40, "size": len(text),
                         "content": base64.encodebytes(text.encode()).decode(), "url": f"{u()}/repos/o/r/contents/{path}", "html_url": "x", "git_url": "x", "download_url": "x"}  # fmt: skip

        def create_ref(rec: Recorded) -> tuple[int, Any]:
            ref = rec.body["ref"]
            if ref in s.refs:
                return 422, {"message": "Reference already exists"}
            s.refs.add(ref)
            return 201, {"ref": ref, "url": f"{u()}/repos/o/r/git/{ref}", "object": {"sha": rec.body["sha"], "type": "commit", "url": "x"}}

        def create_pull(rec: Recorded) -> tuple[int, Any]:
            if s.fail_pull_creation:
                return 422, {"message": "Validation Failed", "errors": [{"message": "No commits between main and head"}]}
            number = len(s.pulls) + 1
            s.pulls.append(pr_json(number, rec.body["head"], rec.body.get("body", ""), rec.body["title"]))
            return 201, s.pulls[-1]

        def label(rec: Recorded, name: str) -> tuple[int, Any]:
            return (200, {"id": 1, "name": name, "color": "ededed", "url": f"{u()}/repos/o/r/labels/{name}"}) if name in s.labels else (404, {"message": "Not Found"})

        def create_label(rec: Recorded) -> tuple[int, Any]:
            s.labels.add(rec.body["name"])
            return 201, {"id": 2, "name": rec.body["name"], "color": rec.body["color"], "url": "x"}

        def tree(rec: Recorded, sha: str) -> tuple[int, Any]:
            return 200, {"sha": sha, "url": "x", "truncated": False, "tree": [{"path": p, "mode": s.modes.get(p, "100644"), "type": "blob", "sha": "f" * 40, "size": 1, "url": "x"} for p in s.files]}

        return [
            ("GET", r"/repos/o/r", lambda rec: (200, repo())),
            ("GET", r"/repos/o/r/branches/main", lambda rec: (200, {"name": "main", "protected": s.protected, "commit": {"sha": BASE_SHA, "url": f"{u()}/repos/o/r/commits/{BASE_SHA}"},
                                                                  "url": f"{u()}/repos/o/r/branches/main", "protection_url": f"{u()}/repos/o/r/branches/main/protection"})),
            ("GET", r"/repos/o/r/branches/main/protection/required_pull_request_reviews", lambda rec: (200, {"require_code_owner_reviews": True, "required_approving_review_count": 1})),
            ("GET", r"/repos/o/r/contents/(.+)", get_contents),
            ("GET", r"/repos/o/r/git/commits/([0-9a-f]{40})", lambda rec, sha: (200, {"sha": sha, "url": "x", "message": "m", "tree": {"sha": TREE_SHA, "url": "x"}, "parents": []})),
            ("GET", r"/repos/o/r/git/trees/([0-9a-f]{40})", tree),
            ("POST", r"/repos/o/r/git/trees", lambda rec: (201, {"sha": TREE_SHA, "url": "x", "tree": []})),
            ("POST", r"/repos/o/r/git/commits", lambda rec: (201, {"sha": COMMIT_SHA, "url": "x", "message": rec.body["message"], "tree": {"sha": rec.body["tree"], "url": "x"}, "parents": []})),
            ("POST", r"/repos/o/r/git/refs", create_ref),
            # GitHub reads a single ref at .../git/ref/{ref} (singular) but writes / deletes at .../git/refs/{ref}
            ("GET", r"/repos/o/r/git/refs?/(.+)", lambda rec, ref: (200, {"ref": f"refs/{ref}", "url": f"{u()}/repos/o/r/git/refs/{ref}", "object": {"sha": COMMIT_SHA, "type": "commit", "url": "x"}})),
            ("DELETE", r"/repos/o/r/git/refs/(.+)", lambda rec, ref: (204, None)),
            ("POST", r"/repos/o/r/pulls", create_pull),
            ("GET", r"/repos/o/r/pulls", lambda rec: (200, s.pulls)),
            ("GET", r"/repos/o/r/issues/(\d+)", lambda rec, n: (200, {"url": f"{u()}/repos/o/r/issues/{n}", "number": int(n), "title": "t", "state": "open", "user": _user(), "labels": []})),
            ("POST", r"/repos/o/r/issues/(\d+)/labels", lambda rec, n: (200, [{"id": 1, "name": x, "color": "ededed", "url": "x"} for x in (rec.body["labels"] if isinstance(rec.body, dict) else rec.body)])),
            ("POST", r"/repos/o/r/pulls/(\d+)/requested_reviewers", lambda rec, n: (201, s.pulls[int(n) - 1])),
            ("GET", r"/repos/o/r/labels/(.+)", label),
            ("POST", r"/repos/o/r/labels", create_label),
            ("GET", r"/repos/o/r/collaborators", lambda rec: (200, [_user(a) for a in s.admins])),
            ("GET", r"/search/code", lambda rec: (200, {"total_count": 1, "incomplete_results": False, "items": [{"name": "client.py", "path": "app/client.py", "sha": "a" * 40, "url": "x", "html_url": "x", "repository": repo()}]})),
            ("GET", r"/repos/psf/requests/releases/tags/(.+)", lambda rec, tag: (200, {"id": 1, "tag_name": tag, "body": "## 2.32.0\n- fix", "url": "x"}) if tag == "v2.32.0" else (404, {"message": "Not Found"})),
            ("GET", r"/repos/psf/requests", lambda rec: (200, {**repo(), "id": 8, "name": "requests", "full_name": "psf/requests", "url": f"{u()}/repos/psf/requests"})),
            ("GET", r"/orgs/o", lambda rec: (200, {"login": "o", "id": 2, "type": "Organization", "url": f"{u()}/orgs/o", "repos_url": f"{u()}/orgs/o/repos"})),
            ("GET", r"/orgs/o/repos", lambda rec: (200, [repo()])),
            ("GET", r"/repos/o/r/topics", lambda rec: (200, {"names": ["python", "cve-exempt"]})),
        ]
