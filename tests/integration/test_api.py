"""Control API through the real ASGI app against real PostgreSQL (Celery replaced by a recording queue)."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import SecretStr
from sqlalchemy import select

from src.agent import runner
from src.agent.deps import override_deps
from src.agent.graph import build_fix_agent_graph
from src.agent.runner import run_fix_agent
from src.api import dependencies as dep
from src.api.main import create_app
from src.api.routers.cves import fix_status
from src.api.routers.jobs import _clean
from src.core.config import settings
from src.core.database import session_scope
from src.models.audit import AuditEvent, PROutcome
from src.models.cve import CVE
from src.models.job import CVERepoImpact, JobStatus, RemediationJob, Repo
from src.services.notifications.dispatcher import NotificationDispatcher
from src.utils import retry as retry_mod
from tests.conftest import FakeContentSource
from tests.fakes import MemoryIdempotency, MemoryNotificationLog, RecordingHandler
from tests.integration.test_graph_core_run import APP, INITIAL, MANIFEST
from tests.llm_helpers import Recorder, chat, good

pytestmark = pytest.mark.db
KEY = "test-api-key"
SECRET = "whsec-test"


class RecordingQueue:
    def __init__(self):
        self.calls: list[tuple] = []

    def _rec(self, name, *args):
        self.calls.append((name, *args))
        return f"task-{len(self.calls)}"

    def sync_cves(self):
        return self._rec("sync_cves")

    def regenerate_sboms(self, repo_names):
        return self._rec("regenerate_sboms", repo_names)

    def generate_sbom(self, repo_name):
        return self._rec("generate_sbom", repo_name)

    def scan_cve(self, cve_id):
        return self._rec("scan_cve", cve_id)

    def enqueue_fix(self, job_id, initial_state):
        return self._rec("enqueue_fix", job_id, initial_state)

    def sync_tracking(self, job_id):
        return self._rec("sync_tracking", job_id)

    def names(self):
        return [c[0] for c in self.calls]


@pytest.fixture
async def api(migrated_db, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", SecretStr(KEY))
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", SecretStr(SECRET))
    monkeypatch.setattr(settings, "CONTROL_API_IP_ALLOWLIST", [])
    app, queue = create_app(), RecordingQueue()
    app.dependency_overrides[dep.get_queue] = lambda: queue
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api", headers={"X-API-Key": KEY}) as client:
        client.queue, client.app_ = queue, app
        yield client


async def seed_job(status=JobStatus.QUEUED, cve_id="CVE-2024-35195", repo="org/api", pr_number=None, with_state=True, **kw) -> str:
    async with session_scope() as s:
        if await s.get(CVE, cve_id) is None:
            s.add(CVE(cve_id=cve_id, source="NVD", severity="MEDIUM", cvss_v3_score=5.6, raw_data={}, published_at=datetime(2024, 5, 1, tzinfo=timezone.utc)))
            await s.flush()
        r = (await s.execute(select(Repo).where(Repo.full_name == repo))).scalar_one_or_none()
        if r is None:
            r = Repo(full_name=repo)
            s.add(r)
            await s.flush()
        job = RemediationJob(job_id=uuid.uuid4(), cve_id=cve_id, repo_id=r.id, repo_name=repo, status=status, affected_package="requests",
                             installed_version="2.31.0", target_version="2.32.0", manifest_file="requirements.txt", pr_number=pr_number, **kw)  # fmt: skip
        s.add(job)
        if with_state:
            s.add(AuditEvent(job_id=job.job_id, cve_id=cve_id, repo_name=repo, event_type="JOB_QUEUED",
                             payload={"run_id": "r1", "initial_state": {**INITIAL, "job_id": str(job.job_id), "run_id": "r1", "repo_name": repo}}))  # fmt: skip
        return str(job.job_id)


# ------------------------------------------------------------------ auth & IP allowlist
async def test_api_key_is_required(api):
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app_), base_url="http://api")
    assert (await anon.get("/api/v1/jobs")).status_code == 401
    assert (await anon.get("/api/v1/jobs", headers={"X-API-Key": "wrong"})).status_code == 401
    assert (await anon.get("/api/v1/jobs", headers={"X-API-Key": KEY})).status_code == 200
    assert (await anon.get("/api/v1/jobs", headers={"X-API-Key": KEY[:-1]})).status_code == 401  # no prefix matching


async def test_every_protected_route_requires_auth(api):
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app_), base_url="http://api")
    jid = str(uuid.uuid4())
    for method, path in [("POST", "/api/v1/scan/trigger"), ("POST", "/api/v1/scan/cve/CVE-2024-1234"), ("GET", "/api/v1/jobs"), ("GET", f"/api/v1/jobs/{jid}"),
                         ("DELETE", f"/api/v1/jobs/{jid}"), ("PATCH", f"/api/v1/jobs/{jid}/pause"), ("POST", f"/api/v1/jobs/{jid}/resume"),
                         ("GET", f"/api/v1/jobs/{jid}/graph-trace"), ("GET", "/api/v1/cves"), ("GET", "/api/v1/config/repos"), ("PATCH", "/api/v1/config/repos")]:  # fmt: skip
        assert (await anon.request(method, path)).status_code == 401, (method, path)


async def test_fails_closed_without_a_configured_key(api, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", None)
    assert (await api.get("/api/v1/jobs")).status_code == 503
    monkeypatch.setattr(settings, "API_KEY", SecretStr(""))
    assert (await api.get("/api/v1/jobs")).status_code == 503


async def test_ip_allowlist(api, monkeypatch):
    monkeypatch.setattr(settings, "CONTROL_API_IP_ALLOWLIST", ["10.0.0.0/8", "192.168.1.5"])
    assert (await api.get("/api/v1/jobs")).status_code == 403  # the ASGI test client connects from 127.0.0.1
    monkeypatch.setattr(settings, "CONTROL_API_IP_ALLOWLIST", ["127.0.0.0/8"])
    assert (await api.get("/api/v1/jobs")).status_code == 200


@pytest.mark.parametrize(
    "host,allow,expected",
    [("10.1.2.3", ["10.0.0.0/8"], True), ("11.1.2.3", ["10.0.0.0/8"], False), ("1.2.3.4", [], True), ("1.2.3.4", ["1.2.3.4"], True),
     ("::1", ["::1/128"], True), (None, ["10.0.0.0/8"], False), ("garbage", ["10.0.0.0/8"], False), ("10.0.0.1", ["not-a-cidr", "10.0.0.0/8"], True)],
)  # fmt: skip
def test_ip_allowed(host, allow, expected):
    assert dep.ip_allowed(host, allow) is expected


async def test_health_is_open_and_reports_dependencies(api, monkeypatch):
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app_), base_url="http://api")
    res = await anon.get("/api/v1/health")
    assert res.status_code == 200 and res.json() == {"status": "ok", "checks": {"database": True, "redis": True}, "automation_enabled": True}
    monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:1/0")  # nothing listens there
    down = await anon.get("/api/v1/health")
    assert down.status_code == 503 and down.json()["checks"] == {"database": True, "redis": False} and down.json()["status"] == "degraded"


# ------------------------------------------------------------------ scan
async def test_scan_trigger_queues_feed_and_sbom_work(api):
    res = await api.post("/api/v1/scan/trigger")
    assert res.status_code == 202 and set(res.json()["task_ids"]) == {"sync_cves", "regenerate_sboms"}
    assert api.queue.calls == [("sync_cves",), ("regenerate_sboms", None)]
    await api.post("/api/v1/scan/trigger", json={"repo_names": ["org/api", "web"]})
    assert api.queue.calls[-1] == ("regenerate_sboms", ["org/api", "web"])


@pytest.mark.parametrize("bad", [["../etc"], ["org/.."], [".."], ["."], ["a b"], ["org/api/extra"], [""], ["x;rm"]])
async def test_scan_trigger_rejects_odd_repo_names(api, bad):
    assert (await api.post("/api/v1/scan/trigger", json={"repo_names": bad})).status_code == 422 and api.queue.calls == []


async def test_scan_cve(api):
    res = await api.post("/api/v1/scan/cve/cve-2024-35195")
    assert res.status_code == 202 and api.queue.calls == [("scan_cve", "CVE-2024-35195")]
    for bad in ("CVE-24-1", "nonsense", "CVE-2024-12;DROP"):
        assert (await api.post(f"/api/v1/scan/cve/{bad}")).status_code == 422


# ------------------------------------------------------------------ jobs: list / detail
async def test_list_jobs_filters_paginates_and_orders(api):
    a = await seed_job(JobStatus.QUEUED, "CVE-2024-0001", "org/api")
    b = await seed_job(JobStatus.PR_RAISED, "CVE-2024-0002", "org/api")
    c = await seed_job(JobStatus.BLOCKED, "CVE-2024-0003", "org/web")
    res = (await api.get("/api/v1/jobs")).json()
    assert res["total"] == 3 and [j["job_id"] for j in res["items"]] == [c, b, a]  # newest first
    assert {j["job_id"] for j in (await api.get("/api/v1/jobs?status=PR_RAISED")).json()["items"]} == {b}
    assert {j["job_id"] for j in (await api.get("/api/v1/jobs?repo=ORG/API")).json()["items"]} == {a, b}
    assert {j["job_id"] for j in (await api.get("/api/v1/jobs?cve=cve-2024-0003")).json()["items"]} == {c}
    page = (await api.get("/api/v1/jobs?limit=1&offset=1")).json()
    assert page["total"] == 3 and len(page["items"]) == 1 and page["items"][0]["job_id"] == b
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert (await api.get("/api/v1/jobs", params={"created_from": future})).json()["total"] == 0
    assert (await api.get("/api/v1/jobs", params={"created_to": future})).json()["total"] == 3
    assert (await api.get("/api/v1/jobs?status=NOPE")).status_code == 422 and (await api.get("/api/v1/jobs?limit=500")).status_code == 422


async def test_job_detail_includes_trail_and_trace_link(api):
    jid = await seed_job(JobStatus.PR_RAISED, confidence_score=90, pr_url="https://github.com/org/api/pull/7", pr_number=7,
                         confidence_breakdown={"tests": 25}, llm_explanation="Bump.")  # fmt: skip
    res = (await api.get(f"/api/v1/jobs/{jid}")).json()
    assert res["status"] == "PR_RAISED" and res["confidence_score"] == 90 and res["confidence_breakdown"] == {"tests": 25}
    assert [e["event_type"] for e in res["events"]] == ["JOB_QUEUED"]
    assert res["graph_trace_url"].endswith(f"/api/v1/jobs/{jid}/graph-trace")
    assert (await api.get(f"/api/v1/jobs/{uuid.uuid4()}")).status_code == 404
    assert (await api.get("/api/v1/jobs/not-a-uuid")).status_code == 422


# ------------------------------------------------------------------ jobs: cancel / pause / resume
async def test_cancel_only_queued_jobs(api):
    queued, running = await seed_job(JobStatus.QUEUED), await seed_job(JobStatus.RUNNING, "CVE-2024-0002")
    res = await api.delete(f"/api/v1/jobs/{queued}")
    assert res.status_code == 200 and res.json()["status"] == "CANCELLED"
    assert (await api.delete(f"/api/v1/jobs/{running}")).status_code == 409
    assert (await api.delete(f"/api/v1/jobs/{queued}")).status_code == 409  # already cancelled
    assert (await api.delete(f"/api/v1/jobs/{uuid.uuid4()}")).status_code == 404
    events = (await api.get(f"/api/v1/jobs/{queued}")).json()["events"]
    assert events[-1]["event_type"] == "JOB_CANCELLED" and events[-1]["payload"] == {"via": "control-api"}


async def test_pause_only_running_jobs(api):
    running, queued = await seed_job(JobStatus.RUNNING), await seed_job(JobStatus.QUEUED, "CVE-2024-0002")
    assert (await api.patch(f"/api/v1/jobs/{running}/pause")).json()["status"] == "PAUSED"
    assert (await api.patch(f"/api/v1/jobs/{running}/pause")).status_code == 409
    assert (await api.patch(f"/api/v1/jobs/{queued}/pause")).status_code == 409
    assert (await api.get(f"/api/v1/jobs/{running}")).json()["events"][-1]["event_type"] == "JOB_PAUSED"


async def test_resume_requeues_with_the_recorded_state(api):
    jid = await seed_job(JobStatus.PAUSED)
    res = await api.post(f"/api/v1/jobs/{jid}/resume")
    assert res.status_code == 202 and res.json()["status"] == "QUEUED"
    (name, job_id, state), = api.queue.calls
    assert name == "enqueue_fix" and job_id == jid and state["run_id"] == "r1" and state["job_id"] == jid  # same run -> resumes its checkpoint
    async with session_scope() as s:
        assert (await s.get(RemediationJob, uuid.UUID(jid))).status == JobStatus.QUEUED  # committed before the message was sent
    assert (await api.get(f"/api/v1/jobs/{jid}")).json()["events"][-1]["event_type"] == "JOB_RESUMED"


async def test_resume_refuses_wrong_states_and_missing_state(api):
    running = await seed_job(JobStatus.RUNNING)
    assert (await api.post(f"/api/v1/jobs/{running}/resume")).status_code == 409
    stateless = await seed_job(JobStatus.PAUSED, "CVE-2024-0002", with_state=False)
    res = await api.post(f"/api/v1/jobs/{stateless}/resume")
    assert res.status_code == 409 and "initial state" in res.json()["detail"]
    assert api.queue.calls == []
    async with session_scope() as s:
        assert (await s.get(RemediationJob, uuid.UUID(stateless))).status == JobStatus.PAUSED  # untouched
    assert (await api.post(f"/api/v1/jobs/{uuid.uuid4()}/resume")).status_code == 404


async def test_a_resumed_job_can_only_be_resumed_once(api):
    jid = await seed_job(JobStatus.PAUSED)
    assert (await api.post(f"/api/v1/jobs/{jid}/resume")).status_code == 202
    assert (await api.post(f"/api/v1/jobs/{jid}/resume")).status_code == 409 and len(api.queue.calls) == 1


# ------------------------------------------------------------------ graph trace
@pytest.fixture
def agent_run(monkeypatch):
    monkeypatch.setattr(runner.settings, "AUTOMATION_ENABLED", True)
    monkeypatch.setattr("src.agent.nodes.fix_generator.default_settings.LLM_API_KEY", SecretStr("k"))

    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


async def test_graph_trace_shows_the_run_step_by_step(api, agent_run, agent_deps):
    jid = await seed_job(JobStatus.RUNNING)
    saver = InMemorySaver()
    src = FakeContentSource(files={"requirements.txt": MANIFEST, "app/client.py": APP}, search={"requests": ["app/client.py"]})
    with agent_deps(src, llm_transport=httpx.MockTransport(Recorder(chat(good())))):
        await run_fix_agent(jid, INITIAL | {"job_id": jid}, checkpointer=saver)

    @asynccontextmanager
    async def factory():
        yield build_fix_agent_graph(saver)

    api.app_.dependency_overrides[dep.get_graph_factory] = lambda: factory
    res = await api.get(f"/api/v1/jobs/{jid}/graph-trace")
    assert res.status_code == 200
    steps = res.json()["steps"]
    ran = [n for s in steps for n in s["ran"]]
    assert ran == ["assemble_context", "assess_reachability", "generate_fix", "score_confidence", "run_sandbox", "run_pre_tests", "apply_patch",
                   "resolve_dependencies", "run_post_tests", "run_security_scan", "cleanup_sandbox", "create_pr", "notify_owners", "write_audit"]  # fmt: skip
    assert [s["step"] for s in steps] == sorted(s["step"] for s in steps)  # oldest first
    assert steps[0]["next"] == [] and steps[1]["next"] == ["assemble_context"]  # step 0 is the bare input
    assert steps[-1]["next"] == [] and steps[-1]["state"]["terminal_status"] == "PR_RAISED"
    assert steps[-1]["state"]["confidence_score"] == 90 and steps[-1]["state"]["audit_event_count"] > 5
    blob = json.dumps(res.json())
    for private in ("requests==2.31.0", "import requests", "context_payload", "llm_raw_response", "original_content"):
        assert private not in blob  # no source code, prompts or file contents leave through the trace


async def test_graph_trace_404_when_the_job_never_ran(api):
    jid = await seed_job()

    @asynccontextmanager
    async def factory():
        yield build_fix_agent_graph(InMemorySaver())

    api.app_.dependency_overrides[dep.get_graph_factory] = lambda: factory
    res = await api.get(f"/api/v1/jobs/{jid}/graph-trace")
    assert res.status_code == 404 and "not started" in res.json()["detail"]
    assert (await api.get(f"/api/v1/jobs/{uuid.uuid4()}/graph-trace")).status_code == 404


def test_trace_values_are_redacted_and_bounded():
    assert "ghp_" not in _clean("failed with token ghp_" + "a" * 36) and len(_clean("x" * 5000)) == 500 and _clean(3) == 3


# ------------------------------------------------------------------ CVEs
@pytest.mark.parametrize(
    "repos,jobs,expected",
    [(0, {}, "no_impact"), (2, {}, "unaddressed"), (2, {"MERGED": 2}, "fixed"), (2, {"MERGED": 1}, "unaddressed"),
     (2, {"MERGED": 1, "RUNNING": 1}, "in_progress"), (2, {"PR_RAISED": 2}, "pr_raised"), (2, {"PR_RAISED": 1, "QUEUED": 1}, "in_progress"),
     (2, {"BLOCKED": 1, "PR_RAISED": 1}, "pr_raised"), (1, {"BLOCKED": 1}, "needs_attention"), (1, {"FAILED": 1}, "needs_attention"), (1, {"PAUSED": 1}, "in_progress")],
)  # fmt: skip
def test_fix_status(repos, jobs, expected):
    assert fix_status(repos, jobs) == expected


async def test_list_cves_with_match_and_fix_status(api):
    async with session_scope() as s:
        for cid, score, sev, kev in [("CVE-2024-0001", 9.8, "CRITICAL", False), ("CVE-2024-0002", 5.0, "MEDIUM", False), ("CVE-2023-0003", 4.1, "MEDIUM", True)]:
            s.add(CVE(cve_id=cid, source="NVD", cvss_v3_score=score, severity=sev, cisa_kev=kev, raw_data={}, title=f"t {cid}"))
    a = await seed_job(JobStatus.PR_RAISED, "CVE-2024-0001", "org/api")
    await seed_job(JobStatus.MERGED, "CVE-2024-0001", "org/web")
    async with session_scope() as s:
        repos = (await s.execute(select(Repo))).scalars().all()
        for r in repos:
            s.add(CVERepoImpact(repo_id=r.id, cve_id="CVE-2024-0001", affected_package="requests", installed_version="2.31.0", manifest_file_path="r.txt"))
    res = (await api.get("/api/v1/cves")).json()
    assert res["total"] == 3
    ids = [c["cve_id"] for c in res["items"]]
    assert ids[0] == "CVE-2023-0003"  # known-exploited first, then by CVSS
    by_id = {c["cve_id"]: c for c in res["items"]}
    top = by_id["CVE-2024-0001"]
    assert top["affected_repos"] == 2 and top["jobs"] == {"PR_RAISED": 1, "MERGED": 1} and top["fix_status"] == "pr_raised" and top["title"] == "t CVE-2024-0001"
    assert by_id["CVE-2024-0002"]["fix_status"] == "no_impact" and by_id["CVE-2024-0002"]["jobs"] == {}
    assert {c["cve_id"] for c in (await api.get("/api/v1/cves?only_affecting=true")).json()["items"]} == {"CVE-2024-0001"}
    assert {c["cve_id"] for c in (await api.get("/api/v1/cves?severity=critical")).json()["items"]} == {"CVE-2024-0001"}
    assert {c["cve_id"] for c in (await api.get("/api/v1/cves?kev=true")).json()["items"]} == {"CVE-2023-0003"}
    assert {c["cve_id"] for c in (await api.get("/api/v1/cves?q=cve-2023")).json()["items"]} == {"CVE-2023-0003"}
    assert len((await api.get("/api/v1/cves?limit=1")).json()["items"]) == 1 and a


# ------------------------------------------------------------------ repo config
async def test_repo_config_defaults_then_override(api):
    first = (await api.get("/api/v1/config/repos")).json()
    assert first["source"] == "static"
    res = await api.patch("/api/v1/config/repos", json={"blocklist": ["Legacy-App", "org/old", "legacy-app"]})
    assert res.json() == {"allowlist": first["allowlist"], "blocklist": ["legacy-app", "org/old"], "source": "override"}  # lower-cased, de-duplicated
    again = (await api.patch("/api/v1/config/repos", json={"allowlist": ["api"]})).json()
    assert again["allowlist"] == ["api"] and again["blocklist"] == ["legacy-app", "org/old"]  # untouched list is kept
    assert (await api.get("/api/v1/config/repos")).json() == again
    cleared = (await api.patch("/api/v1/config/repos", json={"allowlist": []})).json()
    assert cleared["allowlist"] == []


@pytest.mark.parametrize("body", [{"allowlist": ["a b"]}, {"blocklist": ["../x"]}, {"allowlist": [""]}, {"allowlist": "api"}, {"blocklist": [".."]}])
async def test_repo_config_validation(api, body):
    assert (await api.patch("/api/v1/config/repos", json=body)).status_code == 422


# ------------------------------------------------------------------ webhooks
def sign(body: bytes, secret=SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def hook(api, event, payload, delivery=None, secret=SECRET, headers=None):
    body = json.dumps(payload).encode()
    h = {"X-GitHub-Event": event, "X-GitHub-Delivery": delivery or uuid.uuid4().hex, "X-Hub-Signature-256": sign(body, secret), "Content-Type": "application/json"}
    return await api.post("/api/v1/webhooks/github", content=body, headers={**h, **(headers or {})})


@pytest.fixture
def hook_deps():
    handler = RecordingHandler("teams")
    idem = MemoryIdempotency()
    with override_deps(idempotency=idem, dispatcher=NotificationDispatcher([handler], idem, MemoryNotificationLog())):
        yield handler


async def test_webhook_signature_is_enforced(api, hook_deps):
    body = json.dumps({"zen": "x"}).encode()
    base = {"X-GitHub-Event": "ping", "Content-Type": "application/json"}
    assert (await api.post("/api/v1/webhooks/github", content=body, headers=base)).status_code == 401  # missing
    assert (await api.post("/api/v1/webhooks/github", content=body, headers={**base, "X-Hub-Signature-256": sign(body, "wrong")})).status_code == 401
    assert (await api.post("/api/v1/webhooks/github", content=body, headers={**base, "X-Hub-Signature-256": "sha1=abc"})).status_code == 401
    tampered = await api.post("/api/v1/webhooks/github", content=body + b" ", headers={**base, "X-Hub-Signature-256": sign(body)})
    assert tampered.status_code == 401  # signature covers the exact bytes
    ok = await api.post("/api/v1/webhooks/github", content=body, headers={**base, "X-Hub-Signature-256": sign(body)})
    assert ok.status_code == 202 and ok.json()["message"] == "pong"


async def test_webhook_works_without_the_api_key_but_fails_closed_without_a_secret(api, hook_deps, monkeypatch):
    del api.headers["X-API-Key"]  # GitHub cannot send it
    assert (await hook(api, "ping", {})).status_code == 202
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", None)
    assert (await hook(api, "ping", {})).status_code == 503


async def test_webhook_payload_validation(api, hook_deps):
    junk = b"not json"
    res = await api.post("/api/v1/webhooks/github", content=junk, headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sign(junk)})
    assert res.status_code == 400
    big = b"{" + b" " * (6 * 1024 * 1024) + b"}"
    res = await api.post("/api/v1/webhooks/github", content=big, headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sign(big)})
    assert res.status_code == 413


def push_payload(ref="refs/heads/main", name="org/api", default="main", **repo):
    return {"ref": ref, "repository": {"full_name": name, "default_branch": default, **repo}}


async def test_push_to_the_default_branch_refreshes_the_sbom(api, hook_deps):
    res = await hook(api, "push", push_payload())
    assert res.json()["action"] == "sbom_queued" and api.queue.calls == [("generate_sbom", "org/api")]


async def test_other_pushes_are_ignored(api, hook_deps, monkeypatch):
    assert (await hook(api, "push", push_payload(ref="refs/heads/feature"))).json()["status"] == "ignored"
    assert (await hook(api, "push", push_payload(archived=True))).json()["reason"] == "repository is out of scope"
    assert (await hook(api, "push", push_payload(topics=["cve-exempt"]))).json()["status"] == "ignored"
    monkeypatch.setattr(settings, "REPO_BLOCKLIST", ["api"])
    assert (await hook(api, "push", push_payload())).json()["status"] == "ignored"
    assert api.queue.calls == []


async def test_redelivered_webhooks_are_ignored(api, hook_deps):
    assert (await hook(api, "push", push_payload(), delivery="d-1")).json()["status"] == "accepted"
    assert (await hook(api, "push", push_payload(), delivery="d-1")).json() == {"status": "ignored", "reason": "duplicate delivery"}
    assert api.queue.names() == ["generate_sbom"]


async def test_advisory_events_trigger_a_cve_sync(api, hook_deps):
    assert (await hook(api, "security_advisory", {"action": "published"})).json()["action"] == "cve_sync_queued"
    assert (await hook(api, "security_advisory", {"action": "withdrawn"})).json()["status"] == "ignored"
    assert api.queue.names() == ["sync_cves"]


async def test_unhandled_events_are_acknowledged_and_ignored(api, hook_deps):
    for event, payload in [("issues", {"action": "opened"}), ("pull_request", {"action": "opened"}), ("star", {})]:
        assert (await hook(api, event, payload)).json()["status"] == "ignored"
    assert api.queue.calls == []


def pr_payload(job_id, number=7, repo="org/api", merged=True, commits=1, ref=None, body=None):
    return {
        "action": "closed", "repository": {"full_name": repo},
        "pull_request": {"number": number, "merged": merged, "commits": commits, "merged_by": {"login": "alice"} if merged else None,
                         "head": {"ref": ref or "fix/cve-CVE-2024-35195-api-20261009"},
                         "body": body if body is not None else f"text <!-- cve-remediation-bot job_id={job_id} cve=CVE-2024-35195 -->"},
    }  # fmt: skip


async def outcome_of(job_id):
    async with session_scope() as s:
        job = await s.get(RemediationJob, uuid.UUID(job_id))
        out = (await s.execute(select(PROutcome).where(PROutcome.job_id == uuid.UUID(job_id)))).scalar_one_or_none()
        events = [e for (e,) in (await s.execute(select(AuditEvent.event_type).where(AuditEvent.job_id == uuid.UUID(job_id)).order_by(AuditEvent.id))).all()]
        return job.status, out, events


async def test_merged_pr_without_edits_is_recorded_notified_and_tracked(api, hook_deps):
    jid = await seed_job(JobStatus.PR_RAISED, pr_number=7, confidence_score=88, pr_url="https://github.com/org/api/pull/7")
    async with session_scope() as s:
        s.add(AuditEvent(job_id=uuid.UUID(jid), cve_id="CVE-2024-35195", repo_name="org/api", event_type="PR_RAISED", payload={"owners": ["bob@co.com"]}))
    res = await hook(api, "pull_request", pr_payload(jid))
    assert res.json() == {"status": "accepted", "action": "outcome_recorded", "job_id": jid, "outcome": "MERGED_CLEAN"}
    status, out, events = await outcome_of(jid)
    assert status == JobStatus.MERGED and out.outcome == "MERGED_CLEAN" and out.predicted_confidence == 88 and out.pr_number == 7
    assert {"PR_MERGED_CLEAN", "PR_MERGED"} <= set(events)
    (note,) = hook_deps.sent
    assert note.event == "PR_MERGED" and note.recipients == ["bob@co.com"] and note.metadata["outcome"] == "MERGED_CLEAN"
    assert api.queue.calls == [("sync_tracking", jid)]


async def test_merged_pr_with_reviewer_commits_counts_as_edited(api, hook_deps):
    jid = await seed_job(JobStatus.PR_RAISED, pr_number=7, confidence_score=70)
    assert (await hook(api, "pull_request", pr_payload(jid, commits=3))).json()["outcome"] == "MERGED_EDITED"
    status, out, events = await outcome_of(jid)
    assert status == JobStatus.MERGED and out.outcome == "MERGED_EDITED" and "PR_MERGED_EDITED" in events


async def test_rejected_pr_blocks_the_job_so_it_is_not_raised_again(api, hook_deps):
    jid = await seed_job(JobStatus.PR_RAISED, pr_number=7)
    assert (await hook(api, "pull_request", pr_payload(jid, merged=False))).json()["outcome"] == "CLOSED_UNMERGED"
    status, out, events = await outcome_of(jid)
    assert status == JobStatus.BLOCKED and out.outcome == "CLOSED_UNMERGED" and "PR_CLOSED_UNMERGED" in events and "PR_MERGED" not in events
    assert hook_deps.sent == [] and api.queue.names() == ["sync_tracking"]  # no "merged" notification, but JIRA/Confluence are updated


async def test_a_second_close_event_does_not_double_count(api, hook_deps):
    jid = await seed_job(JobStatus.PR_RAISED, pr_number=7)
    await hook(api, "pull_request", pr_payload(jid))
    again = await hook(api, "pull_request", pr_payload(jid))
    assert again.json()["reason"] == "outcome already recorded" and len(hook_deps.sent) == 1
    async with session_scope() as s:
        assert len((await s.execute(select(PROutcome))).scalars().all()) == 1


@pytest.mark.parametrize(
    "tweak",
    [{"repo": "other/repo"}, {"number": 99}, {"ref": "feature/not-ours"}, {"body": "no marker here"}, {"body": "<!-- cve-remediation-bot job_id=not-a-uuid cve=CVE-1-1 -->"}],
)  # fmt: skip
async def test_prs_that_are_not_ours_are_ignored(api, hook_deps, tweak):
    jid = await seed_job(JobStatus.PR_RAISED, pr_number=7)
    payload = pr_payload(jid, **tweak)
    assert (await hook(api, "pull_request", payload)).json()["status"] == "ignored"
    status, out, _ = await outcome_of(jid)
    assert status == JobStatus.PR_RAISED and out is None and hook_deps.sent == []  # a forged marker changes nothing


async def test_unknown_job_marker_is_ignored(api, hook_deps):
    assert (await hook(api, "pull_request", pr_payload(str(uuid.uuid4())))).json()["status"] == "ignored"
