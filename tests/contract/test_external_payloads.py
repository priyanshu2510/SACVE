"""Every payload we SEND must satisfy the provider's documented schema; every response we RELY ON must be parsed correctly."""

from __future__ import annotations

import hashlib
import hmac
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx
import pytest
from pydantic import SecretStr

from src.agent.nodes import fix_generator as fg
from src.agent.nodes.fix_generator import LLMClient, LLMResponseError
from src.api.routers.webhooks import verify_signature
from src.core.config import Settings
from src.services.atlassian import AtlassianClient
from src.services.confluence.publisher import ConfluencePublisher, render_cve_page, render_daily_page
from src.services.jira.issue_creator import JiraIssueCreator, TicketContext
from src.services.notifications.base import Notification
from src.services.notifications.pagerduty import PagerDutyHandler
from src.services.notifications.teams import TeamsHandler
from src.services.notifications.webhook import WebhookHandler, sign
from src.utils import retry as retry_mod
from tests.contract import schemas as S


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def note(**kw) -> Notification:
    base = dict(event="PR_RAISED", job_id="j1", cve_id="CVE-2024-35195", repo_name="org/api", severity="HIGH", subject="Fix ready",
                body="Body", recipients=["alice@co.com"], metadata={"pr_url": "https://pr", "cvss": 9.8})  # fmt: skip
    return Notification(**(base | kw))


# ==================================================================================================== LLM
class Capture:
    def __init__(self, response: httpx.Response):
        self.response, self.requests = response, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


def llm(response: httpx.Response) -> tuple[LLMClient, Capture]:
    cap = Capture(response)
    cfg = Settings(_env_file=None, LLM_API_KEY=SecretStr("k"), LLM_API_BASE_URL="https://llm.example/v1", LLM_MODEL_NAME="m1")
    return LLMClient(cfg, transport=httpx.MockTransport(cap)), cap


OPENAI_OK = httpx.Response(200, json={"id": "x", "object": "chat.completion", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "{}"}}], "usage": {"total_tokens": 3}})


async def test_llm_request_satisfies_the_chat_completions_schema():
    client, cap = llm(OPENAI_OK)
    async with client:
        await client.complete([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}])
    (req,) = cap.requests
    S.assert_valid(S.LLM_REQUEST, json.loads(req.content))
    assert req.url.path == "/v1/chat/completions" and req.method == "POST" and req.headers["authorization"] == "Bearer k"
    assert req.headers["content-type"] == "application/json"


async def test_llm_real_request_built_by_the_fix_generator_is_valid(make_state):
    """The actual prompt (not a toy one) also satisfies the schema, including size limits on content being strings."""
    from src.agent.deps import override_deps

    state = make_state(context_payload={"cve": {"description": "d" * 50}, "manifest": {"path": "requirements.txt", "content": "requests==2.31.0\n"},
                                        "source_files": [], "file_allowlist": ["requirements.txt"]})  # fmt: skip
    cap = Capture(httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": json.dumps({
        "file_changes": [{"file_path": "requirements.txt", "change_description": "b", "original_content": "requests==2.31.0", "new_content": "requests==2.32.0"}],
        "explanation": "e", "breaking_change_risk": "low", "breaking_change_notes": None, "self_confidence": 90})}}]}))
    from src.core.config import settings

    settings.LLM_API_KEY = SecretStr("k")
    try:
        with override_deps(llm_transport=httpx.MockTransport(cap)):
            out = await fg.generate_fix(state)
    finally:
        settings.LLM_API_KEY = None
    assert "error" not in out
    S.assert_valid(S.LLM_REQUEST, json.loads(cap.requests[0].content))


@pytest.mark.parametrize(
    "response,ok",
    [
        (OPENAI_OK, True),
        (httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "{}"}}]}), True),  # usage is optional
        (httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{"id": "1"}]}}]}), False),  # tool call, no text
        (httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": ""}}]}), False),
        (httpx.Response(200, json={"choices": []}), False),
        (httpx.Response(200, json={"error": {"message": "rate limited"}}), False),  # 200 with an error body (some gateways do this)
        (httpx.Response(200, json=["not", "an", "object"]), False),
    ],
)  # fmt: skip
async def test_llm_response_shapes(response, ok):
    client, _ = llm(response)
    async with client:
        if ok:
            text, _usage = await client.complete([{"role": "user", "content": "u"}])
            assert isinstance(text, str) and text
        else:
            with pytest.raises((LLMResponseError, TypeError, AttributeError)):
                await client.complete([{"role": "user", "content": "u"}])


def test_the_response_schema_matches_what_the_client_accepts():
    S.assert_valid(S.LLM_RESPONSE, OPENAI_OK.json())


# ==================================================================================================== Teams / PagerDuty / webhook
async def test_teams_payload_matches_the_assumed_contract():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"], seen["headers"] = json.loads(request.content), request.headers
        return httpx.Response(200, json={})

    h = TeamsHandler(Settings(_env_file=None, TEAMS_API_KEY="tk", TEAMS_API_ENDPOINT="https://teams.example/api/notify"), httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await h.send(note())
    S.assert_valid(S.TEAMS_REQUEST, seen["body"])
    assert seen["headers"]["authorization"] == "Bearer tk" and seen["headers"]["content-type"] == "application/json"


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
async def test_teams_accepts_every_severity_we_can_send(severity):
    seen = {}
    h = TeamsHandler(Settings(_env_file=None, TEAMS_API_KEY="tk"), httpx.AsyncClient(transport=httpx.MockTransport(lambda r: (seen.update(json.loads(r.content)), httpx.Response(200))[1])))
    await h.send(note(severity=severity))
    S.assert_valid(S.TEAMS_REQUEST, seen)


async def test_pagerduty_payload_matches_events_api_v2():
    seen = {}
    h = PagerDutyHandler(Settings(_env_file=None, PAGERDUTY_ROUTING_KEY="R" * 32), httpx.AsyncClient(transport=httpx.MockTransport(lambda r: (seen.update(json.loads(r.content)), httpx.Response(202))[1])))
    await h.send(note(event="ESCALATED", subject="x" * 3000))  # longer than PagerDuty allows
    S.assert_valid(S.PAGERDUTY_REQUEST, seen)
    assert len(seen["payload"]["summary"]) <= 1024 and seen["event_action"] == "trigger"


async def test_outbound_webhook_is_signed_like_github_webhooks():
    seen = {}
    h = WebhookHandler(Settings(_env_file=None, WEBHOOK_URL="https://hook.example/x", WEBHOOK_SECRET="s"), httpx.AsyncClient(transport=httpx.MockTransport(lambda r: (seen.update(sig=r.headers["x-signature-256"], raw=r.content), httpx.Response(200))[1])))
    await h.send(note())
    assert seen["sig"] == "sha256=" + hmac.new(b"s", seen["raw"], hashlib.sha256).hexdigest() == sign("s", seen["raw"])


def test_github_documented_webhook_test_vector():
    """GitHub's own example from 'Validating webhook deliveries' - guards against any drift from the real algorithm."""
    secret, payload = "It's a Secret to Everybody", b"Hello, World!"
    header = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    assert verify_signature(secret, payload, header)
    assert not verify_signature(secret, payload + b"!", header) and not verify_signature("other", payload, header)
    assert not verify_signature(secret, payload, header.replace("sha256=", "sha1=")) and not verify_signature(secret, payload, None)
    assert sign(secret, payload) == header


# ==================================================================================================== JIRA
class Jira:
    """Records requests and answers with documented JIRA response shapes."""

    def __init__(self):
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/rest/api/3/search/jql":
            return httpx.Response(200, json={"issues": []})
        if path == "/rest/api/3/user/search":
            return httpx.Response(200, json=[{"accountId": "5b10ac8d82e05b22cc7d4ef5", "accountType": "atlassian", "displayName": "A"}])
        if path == "/rest/api/3/issue" and request.method == "POST":
            return httpx.Response(201, json={"id": "10000", "key": "SEC-1", "self": "https://x/rest/api/3/issue/10000"})
        if path.endswith("/transitions") and request.method == "GET":
            return httpx.Response(200, json={"transitions": [{"id": "21", "name": "Start review", "to": {"id": "3", "name": "In Review"}}]})
        if "/issue/SEC-1" in path and request.method == "GET":
            return httpx.Response(200, json={"fields": {"status": {"name": "To Do"}}})
        return httpx.Response(204) if request.method in ("PUT", "POST") and "comment" not in path else httpx.Response(201, json={})

    def body(self, method: str, suffix: str) -> dict:
        return json.loads(next(r for r in self.requests if r.method == method and r.url.path.endswith(suffix)).content)


def jira_creator(j: Jira) -> JiraIssueCreator:
    cfg = Settings(_env_file=None, JIRA_PROJECT_KEY="SEC", JIRA_BASE_URL="https://co.atlassian.net")
    return JiraIssueCreator(cfg, AtlassianClient("https://co.atlassian.net", "bot@co.com", "t", httpx.AsyncClient(transport=httpx.MockTransport(j.handler))))


CTX = TicketContext("0b8f3a52-1e0f-4d8e-9d36-0a9a5f2a8a11", "CVE-2024-35195", "HIGH", 7.5, "org/api", "requests", "2.31.0", "2.32.0", "PR_RAISED",
                    pr_url="https://github.com/org/api/pull/7", confluence_url="https://co.atlassian.net/wiki/x", owner_emails=["alice@co.com"], issue_key="SEC-1")  # fmt: skip


async def test_every_jira_request_satisfies_the_v3_schemas():
    j = Jira()
    c = jira_creator(j)
    key = await c.create_issue(CTX)
    await c.update_description(key, CTX)
    await c.comment(key, "Pull request raised for review:", CTX.pr_url)
    await c.assign(key, "alice@co.com")
    await c.transition_to(key, "In Review")
    S.assert_valid(S.JIRA_SEARCH_JQL, j.body("POST", "/search/jql"))
    S.assert_valid(S.JIRA_CREATE_ISSUE, j.body("POST", "/rest/api/3/issue"))
    S.assert_valid(S.JIRA_UPDATE_DESCRIPTION, j.body("PUT", "/rest/api/3/issue/SEC-1"))
    S.assert_valid(S.JIRA_COMMENT, j.body("POST", "/comment"))
    S.assert_valid(S.JIRA_ASSIGNEE, j.body("PUT", "/assignee"))
    S.assert_valid(S.JIRA_TRANSITION, j.body("POST", "/transitions"))
    assert key == "SEC-1"


@pytest.mark.parametrize("severity,pkg,repo", [("CRITICAL", "x" * 400, "org/repo"), ("HIGH", "pkg", "org/rép\nname"), ("LOW", "a b", "o/r")])
async def test_jira_create_is_valid_for_awkward_input(severity, pkg, repo):
    j = Jira()
    await jira_creator(j).create_issue(TicketContext(**{**CTX.__dict__, "severity": severity, "package": pkg, "repo_name": repo, "pr_url": "javascript:alert(1)"}))
    S.assert_valid(S.JIRA_CREATE_ISSUE, j.body("POST", "/rest/api/3/issue"))  # 255-char summary, no newlines, only http(s) links, whitespace-free labels


def test_jira_responses_we_depend_on_are_documented_shapes():
    S.assert_valid(S.JIRA_CREATE_RESPONSE, {"id": "10000", "key": "SEC-1", "self": "https://x"})
    S.assert_valid(S.JIRA_TRANSITIONS_RESPONSE, {"expand": "transitions", "transitions": [{"id": "21", "name": "Start", "to": {"name": "In Review"}}]})
    S.assert_valid(S.JIRA_SEARCH_RESPONSE, {"issues": [{"id": "1", "key": "SEC-1"}], "isLast": True})


# ==================================================================================================== Confluence
class Wiki:
    def __init__(self, existing: bool):
        self.existing, self.requests = existing, []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        page = {"id": "12345", "type": "page", "title": "T", "version": {"number": 4}, "_links": {"base": "https://co.atlassian.net/wiki", "webui": "/spaces/SEC/pages/12345/T"}}
        if request.method == "GET":
            return httpx.Response(200, json={"results": [page] if self.existing else [], "size": 1 if self.existing else 0})
        return httpx.Response(200, json=page)

    def body(self, method: str) -> dict:
        return json.loads(next(r for r in self.requests if r.method == method).content)


def publisher(w: Wiki) -> ConfluencePublisher:
    cfg = Settings(_env_file=None, CONFLUENCE_SPACE_KEY="SEC", CONFLUENCE_PARENT_PAGE_ID="123456")
    return ConfluencePublisher(cfg, AtlassianClient("https://co.atlassian.net", "bot@co.com", "t", httpx.AsyncClient(transport=httpx.MockTransport(w.handler))))


async def test_confluence_create_and_update_satisfy_the_v1_schemas():
    w = Wiki(existing=False)
    ref = await publisher(w).upsert_page("A page", "<p>x</p>")
    S.assert_valid(S.CONFLUENCE_CREATE, w.body("POST"))
    S.assert_valid(S.CONFLUENCE_PAGE_RESPONSE, {"id": ref.id, "title": ref.title, "_links": {"webui": "/x"}})
    w2 = Wiki(existing=True)
    await publisher(w2).upsert_page("A page", "<p>y</p>")
    S.assert_valid(S.CONFLUENCE_UPDATE, w2.body("PUT"))
    assert w2.body("PUT")["version"]["number"] == 5  # current version + 1


def test_confluence_search_response_shape():
    S.assert_valid(S.CONFLUENCE_SEARCH_RESPONSE, {"results": [{"id": "1", "version": {"number": 2}}]})


HOSTILE = ["<script>alert(1)</script>", "a & b < c > d", 'quote " and \' apostrophe', "ünïcödé ✓ — “smart quotes”", "]]> CDATA end", "&nbsp; &copy;"]


@pytest.mark.parametrize("text", HOSTILE)
def test_confluence_storage_format_is_well_formed_xml_for_hostile_text(text):
    """Confluence's storage format is XHTML: any unescaped character breaks the page (or injects markup)."""
    job = {"job_id": "j", "cve_id": "CVE-2024-1", "repo_name": f"org/{text}", "status": "PR_RAISED", "affected_package": text, "installed_version": "1", "target_version": "2",
           "severity": "HIGH", "cvss": 7.5, "pr_url": "https://github.com/o/r/pull/1?a=1&b=2", "jira_issue_key": text}  # fmt: skip
    events = [{"ts": "2026-10-09T00:00:00+00:00", "event_type": "X", "payload": {"note": text}}]
    ET.fromstring(f"<root>{render_cve_page(job, events)}</root>")
    ET.fromstring(f"<root>{render_daily_page(datetime(2026, 10, 9, tzinfo=timezone.utc), {'cves': 1, 'jobs': 1, 'repos': 1, 'by_status': {text: 1}}, [{'cve_id': text, 'repo_name': text, 'status': text, 'pr_url': 'https://x/?a=1&b=2', 'jira_issue_key': text}])}</root>")
    rendered = render_cve_page(job, events)
    assert "<script>" not in rendered
