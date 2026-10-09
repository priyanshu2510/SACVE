import base64
import json
from datetime import datetime, timezone

import httpx
import pytest

from src.core.config import Settings
from src.services.atlassian import AtlassianClient, AtlassianError
from src.services.confluence.publisher import (
    ConfluencePublisher, cve_page_title, daily_page_title, event_summary, link, render_cve_page, render_daily_page,
)  # fmt: skip
from src.services.jira.issue_creator import JiraIssueCreator, TicketContext, adf, description, job_label, summary
from src.utils import retry as retry_mod

CFG = Settings(_env_file=None, CONFLUENCE_SPACE_KEY="SEC", CONFLUENCE_PARENT_PAGE_ID="123456", JIRA_PROJECT_KEY="SEC")


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


class Server:
    """MockTransport handler: routes by ``METHOD path`` and records requests."""

    def __init__(self, routes):
        self.routes, self.requests = routes, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = f"{request.method} {request.url.path}"
        handler = self.routes.get(key)
        if handler is None:
            return httpx.Response(404, json={"message": f"no route {key}"})
        if isinstance(handler, list):
            handler = handler.pop(0) if len(handler) > 1 else handler[0]
        return handler(request) if callable(handler) else handler

    def bodies(self, method, path):
        return [json.loads(r.content) for r in self.requests if r.method == method and r.url.path == path]


def client(server: Server) -> AtlassianClient:
    return AtlassianClient("https://co.atlassian.net", "bot@co.com", "tok", httpx.AsyncClient(transport=httpx.MockTransport(server)))


# ------------------------------------------------------------------ AtlassianClient
async def test_basic_auth_and_json():
    server = Server({"GET /x": httpx.Response(200, json={"ok": 1})})
    assert await client(server).request("GET", "/x") == {"ok": 1}
    token = base64.b64encode(b"bot@co.com:tok").decode()
    assert server.requests[0].headers["authorization"] == f"Basic {token}"


async def test_error_status_carries_atlassians_message():
    server = Server({"POST /x": httpx.Response(400, json={"errorMessages": ["bad"], "errors": {"priority": "not on screen"}})})
    with pytest.raises(AtlassianError) as exc:
        await client(server).request("POST", "/x", json={})
    assert exc.value.status == 400 and "bad" in exc.value.message and "priority" in exc.value.message


async def test_transient_errors_are_retried_but_client_errors_are_not():
    flaky = Server({"GET /x": [httpx.Response(503), httpx.Response(429), httpx.Response(200, json={"ok": 1})]})
    assert await client(flaky).request("GET", "/x") == {"ok": 1} and len(flaky.requests) == 3
    denied = Server({"GET /x": httpx.Response(403, json={"message": "forbidden"})})
    with pytest.raises(AtlassianError):
        await client(denied).request("GET", "/x")
    assert len(denied.requests) == 1


async def test_empty_204_body():
    assert await client(Server({"PUT /x": httpx.Response(204)})).request("PUT", "/x") is None


# ------------------------------------------------------------------ Confluence
PAGE = {"id": "777", "title": "T", "_links": {"base": "https://co.atlassian.net/wiki", "webui": "/spaces/SEC/pages/777/T"}, "version": {"number": 3}}


async def test_creates_a_page_under_the_parent():
    server = Server({"GET /wiki/rest/api/content": httpx.Response(200, json={"results": []}), "POST /wiki/rest/api/content": httpx.Response(200, json=PAGE)})
    ref = await ConfluencePublisher(CFG, client(server)).upsert_page("T", "<p>x</p>")
    assert ref.id == "777" and ref.url == "https://co.atlassian.net/wiki/spaces/SEC/pages/777/T"
    (body,) = server.bodies("POST", "/wiki/rest/api/content")
    assert body["space"] == {"key": "SEC"} and body["ancestors"] == [{"id": "123456"}]
    assert body["body"]["storage"] == {"value": "<p>x</p>", "representation": "storage"}
    assert dict(server.requests[0].url.params)["title"] == "T" and dict(server.requests[0].url.params)["spaceKey"] == "SEC"


async def test_updates_an_existing_page_with_the_next_version():
    server = Server({"GET /wiki/rest/api/content": httpx.Response(200, json={"results": [PAGE]}), "PUT /wiki/rest/api/content/777": httpx.Response(200, json=PAGE)})
    await ConfluencePublisher(CFG, client(server)).upsert_page("T", "<p>new</p>")
    (body,) = server.bodies("PUT", "/wiki/rest/api/content/777")
    assert body["version"] == {"number": 4} and body["body"]["storage"]["value"] == "<p>new</p>"
    assert not server.bodies("POST", "/wiki/rest/api/content")


async def test_lost_creation_race_falls_back_to_update():
    server = Server({
        "GET /wiki/rest/api/content": [httpx.Response(200, json={"results": []}), httpx.Response(200, json={"results": [PAGE]})],
        "POST /wiki/rest/api/content": httpx.Response(400, json={"message": "A page with this title already exists"}),
        "PUT /wiki/rest/api/content/777": httpx.Response(200, json=PAGE),
    })  # fmt: skip
    assert (await ConfluencePublisher(CFG, client(server)).upsert_page("T", "x")).id == "777"


async def test_other_confluence_errors_propagate():
    server = Server({"GET /wiki/rest/api/content": httpx.Response(200, json={"results": []}), "POST /wiki/rest/api/content": httpx.Response(403, json={"message": "no permission"})})
    with pytest.raises(AtlassianError, match="403"):
        await ConfluencePublisher(CFG, client(server)).upsert_page("T", "x")


JOB = {"job_id": "j-1", "cve_id": "CVE-2024-35195", "repo_name": "org/api", "status": "PR_RAISED", "affected_package": "requests",
       "installed_version": "2.31.0", "target_version": "2.32.0", "confidence_score": 90, "attempt_count": 2, "severity": "MEDIUM", "cvss": 5.6,
       "pr_url": "https://github.com/org/api/pull/7", "jira_issue_key": "SEC-9"}  # fmt: skip


def test_cve_page_is_escaped_and_complete():
    events = [{"ts": "2026-10-09T00:00:00+00:00", "event_type": "FIX_GENERATED", "payload": {"explanation": "<script>alert(1)</script>"}}]
    page = render_cve_page(JOB | {"repo_name": "org/<b>api"}, events)
    assert "<script>" not in page and "&lt;script&gt;" in page and "org/&lt;b&gt;api" in page
    for needle in ["CVE-2024-35195", "2.31.0 → 2.32.0", "90 / 100", "SEC-9", 'href="https://github.com/org/api/pull/7"', "FIX_GENERATED", "Audit timeline"]:
        assert needle in page, needle


def test_link_only_allows_http_urls():
    assert link("javascript:alert(1)") == "—" and link(None) == "—" and link("") == "—"
    assert link('https://x/"><b>') .startswith('<a href="https://x/&quot;&gt;&lt;b&gt;')


def test_event_summary_is_capped():
    assert len(event_summary({"k": "v" * 5000})) <= 401


def test_titles_are_stable_and_unique_per_pair():
    assert cve_page_title("CVE-1", "org/a") != cve_page_title("CVE-1", "org/b")
    assert daily_page_title(datetime(2026, 10, 9, tzinfo=timezone.utc)) == "CVE Remediation Daily Run – 2026-10-09"


def test_daily_page():
    page = render_daily_page(datetime(2026, 10, 9, tzinfo=timezone.utc), {"cves": 4, "jobs": 2, "repos": 1, "by_status": {"PR_RAISED": 1, "BLOCKED": 1}},
                             [{"cve_id": "CVE-1", "repo_name": "org/api", "status": "PR_RAISED", "pr_url": "https://x/pr/1", "jira_issue_key": "SEC-1"}])  # fmt: skip
    for needle in ["2026-10-09", "CVEs added or updated", "PR_RAISED", "BLOCKED", "org/api", "SEC-1", 'href="https://x/pr/1"']:
        assert needle in page, needle


# ------------------------------------------------------------------ JIRA
CTX = TicketContext("job-1", "CVE-2024-35195", "HIGH", 7.5, "org/api", "requests", "2.31.0", "2.32.0", "QUEUED", owner_emails=["alice@co.com"])


def jira(server) -> JiraIssueCreator:
    return JiraIssueCreator(CFG, client(server))


def create_routes(**over):
    routes = {
        "POST /rest/api/3/search/jql": httpx.Response(200, json={"issues": []}),
        "GET /rest/api/3/user/search": httpx.Response(200, json=[{"accountId": "acc-1", "accountType": "atlassian"}]),
        "POST /rest/api/3/issue": httpx.Response(201, json={"key": "SEC-42"}),
    }
    return routes | over


async def test_creates_a_ticket_with_the_spec_field_mapping():
    server = Server(create_routes())
    assert await jira(server).create_issue(CTX) == "SEC-42"
    (body,) = server.bodies("POST", "/rest/api/3/issue")
    f = body["fields"]
    assert f["project"] == {"key": "SEC"} and f["issuetype"] == {"name": "Task"}
    assert f["priority"] == {"name": "P2 - High"} and f["assignee"] == {"accountId": "acc-1"}
    assert "cve-job-job-1" in f["labels"] and {"security", "cve-fix", "automated"} <= set(f["labels"])
    assert f["summary"] == "[CVE-2024-35195] HIGH: bump requests 2.31.0 → 2.32.0 in api"
    assert f["description"]["type"] == "doc" and f["description"]["version"] == 1  # ADF, not a string


async def test_priority_follows_severity():
    for severity, name in [("CRITICAL", "P1 - Critical"), ("HIGH", "P2 - High"), ("MEDIUM", "P3 - Medium"), ("LOW", "P4 - Low")]:
        server = Server(create_routes())
        await jira(server).create_issue(TicketContext(**{**CTX.__dict__, "severity": severity}))
        assert server.bodies("POST", "/rest/api/3/issue")[0]["fields"]["priority"] == {"name": name}


async def test_existing_ticket_for_the_job_is_reused():
    server = Server(create_routes(**{"POST /rest/api/3/search/jql": httpx.Response(200, json={"issues": [{"key": "SEC-7"}]})}))
    assert await jira(server).create_issue(CTX) == "SEC-7" and not server.bodies("POST", "/rest/api/3/issue")
    assert job_label("job-1") in server.bodies("POST", "/rest/api/3/search/jql")[0]["jql"]


async def test_no_assignee_when_the_user_is_not_found():
    server = Server(create_routes(**{"GET /rest/api/3/user/search": httpx.Response(200, json=[])}))
    await jira(server).create_issue(CTX)
    assert "assignee" not in server.bodies("POST", "/rest/api/3/issue")[0]["fields"]


async def test_fields_the_project_does_not_expose_are_dropped_and_retried():
    server = Server(create_routes(**{"POST /rest/api/3/issue": [
        httpx.Response(400, json={"errors": {"priority": "Field 'priority' cannot be set. It is not on the appropriate screen"}}),
        httpx.Response(201, json={"key": "SEC-43"})]}))  # fmt: skip
    assert await jira(server).create_issue(CTX) == "SEC-43"
    first, second = server.bodies("POST", "/rest/api/3/issue")
    assert "priority" in first["fields"] and "priority" not in second["fields"] and "summary" in second["fields"]


async def test_other_validation_errors_are_not_swallowed():
    server = Server(create_routes(**{"POST /rest/api/3/issue": httpx.Response(400, json={"errors": {"project": "bad project"}})}))
    with pytest.raises(AtlassianError, match="bad project"):
        await jira(server).create_issue(CTX)


def test_only_critical_and_high_get_tickets():
    j = JiraIssueCreator(CFG, client(Server({})))
    assert j.wants("critical") and j.wants("HIGH") and not j.wants("MEDIUM") and not j.wants("LOW")
    assert j.issue_url("SEC-1") == "https://company.atlassian.net/browse/SEC-1"


def test_description_links_only_when_known_and_safe():
    plain = json.dumps(description(CTX))
    assert "Pull request" not in plain and "Audit trail" not in plain
    full = json.dumps(description(TicketContext(**{**CTX.__dict__, "pr_url": "https://gh/pr/1", "confluence_url": "https://wiki/p"})))
    assert "https://gh/pr/1" in full and "https://wiki/p" in full and '"type": "link"' in full
    unsafe = json.dumps(description(TicketContext(**{**CTX.__dict__, "pr_url": "javascript:alert(1)"})))
    assert '"href": "javascript' not in unsafe


def test_summary_is_one_line_and_bounded():
    s = summary(TicketContext(**{**CTX.__dict__, "package": "x" * 400, "repo_name": "o/r\nname"}))
    assert "\n" not in s and len(s) <= 250
    assert adf()["content"] == []


TRANSITIONS = {"transitions": [{"id": "11", "name": "Start review", "to": {"name": "In Review"}}, {"id": "31", "name": "Complete", "to": {"name": "Done"}}]}


def status_routes(current):
    return {
        "GET /rest/api/3/issue/SEC-1": httpx.Response(200, json={"fields": {"status": {"name": current}}}),
        "GET /rest/api/3/issue/SEC-1/transitions": httpx.Response(200, json=TRANSITIONS),
        "POST /rest/api/3/issue/SEC-1/transitions": httpx.Response(204),
    }


async def test_transition_by_destination_status_name():
    server = Server(status_routes("To Do"))
    assert await jira(server).transition_to("SEC-1", "in review") is True
    assert server.bodies("POST", "/rest/api/3/issue/SEC-1/transitions") == [{"transition": {"id": "11"}}]


async def test_transition_by_transition_name_and_noop_when_already_there():
    server = Server(status_routes("To Do"))
    assert await jira(server).transition_to("SEC-1", "Complete") is True
    assert server.bodies("POST", "/rest/api/3/issue/SEC-1/transitions") == [{"transition": {"id": "31"}}]
    again = Server(status_routes("Done"))
    assert await jira(again).transition_to("SEC-1", "Done") is True and not again.bodies("POST", "/rest/api/3/issue/SEC-1/transitions")


async def test_unavailable_transition_is_reported_not_raised():
    server = Server(status_routes("To Do"))
    assert await jira(server).transition_to("SEC-1", "Blocked") is False


async def test_sync_status_uses_the_configured_mapping():
    server = Server(status_routes("To Do"))
    j = jira(server)
    assert await j.sync_status(TicketContext(**{**CTX.__dict__, "status": "PR_RAISED", "issue_key": "SEC-1"})) is True
    assert await j.sync_status(TicketContext(**{**CTX.__dict__, "status": "RUNNING", "issue_key": "SEC-1"})) is False  # no mapping
    assert await j.sync_status(TicketContext(**{**CTX.__dict__, "status": "MERGED", "issue_key": None})) is False


async def test_assign_and_comment():
    server = Server({"GET /rest/api/3/user/search": httpx.Response(200, json=[{"accountId": "acc-9"}]),
                     "PUT /rest/api/3/issue/SEC-1/assignee": httpx.Response(204),
                     "POST /rest/api/3/issue/SEC-1/comment": httpx.Response(201, json={})})  # fmt: skip
    j = jira(server)
    assert await j.assign("SEC-1", "bob@co.com") is True
    assert server.bodies("PUT", "/rest/api/3/issue/SEC-1/assignee") == [{"accountId": "acc-9"}]
    await j.comment("SEC-1", "PR raised:", "https://gh/pr/1")
    assert "https://gh/pr/1" in json.dumps(server.bodies("POST", "/rest/api/3/issue/SEC-1/comment")[0])
    assert await JiraIssueCreator(CFG, client(Server({"GET /rest/api/3/user/search": httpx.Response(200, json=[])}))).assign("SEC-1", "x@y.com") is False
