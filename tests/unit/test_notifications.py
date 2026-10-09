import hashlib
import hmac
import json

import httpx
import pytest
from pydantic import SecretStr

from src.core.config import Settings
from src.services.notifications import base
from src.services.notifications.base import Notification, resolve_recipients
from src.services.notifications.dispatcher import NotificationDispatcher, build_handlers
from src.services.notifications.email import EmailHandler
from src.services.notifications.pagerduty import PagerDutyHandler
from src.services.notifications.teams import TeamsHandler
from src.services.notifications.webhook import WebhookHandler, sign
from src.utils import retry as retry_mod
from tests.fakes import MemoryIdempotency, MemoryNotificationLog, RecordingHandler


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _sleep(_):
        return None

    monkeypatch.setattr(retry_mod.asyncio, "sleep", _sleep)


def note(**kw) -> Notification:
    base_kw = dict(event="PR_RAISED", job_id="job-1", cve_id="CVE-2024-35195", repo_name="org/api", severity="HIGH",
                   subject="Fix ready", body="Body text", recipients=["alice@corp.com", "@bob"], metadata={"pr_url": "https://pr", "cvss": 7.5})  # fmt: skip
    return Notification(**(base_kw | kw))


def cfg(**env) -> Settings:
    return Settings(_env_file=None, **env)


def http(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ------------------------------------------------------------------ recipients
def test_resolve_recipients(monkeypatch):
    monkeypatch.setattr(base.settings, "OWNER_EMAIL_DOMAIN", None)
    assert resolve_recipients(["@alice", "bob@corp.com", "@org/team", "@ALICE"]) == ["@alice", "bob@corp.com", "@org/team"]
    monkeypatch.setattr(base.settings, "OWNER_EMAIL_DOMAIN", "corp.com")
    assert resolve_recipients(["@alice", "bob@corp.com", "@org/team"]) == ["alice@corp.com", "bob@corp.com", "@org/team"]


def test_email_recipients_property():
    assert note().email_recipients == ["alice@corp.com"]


# ------------------------------------------------------------------ channels
async def test_teams_payload_and_auth():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["auth"], seen["body"] = req.headers["authorization"], json.loads(req.content)
        return httpx.Response(200, json={})

    h = TeamsHandler(cfg(TEAMS_API_KEY="tk", TEAMS_API_ENDPOINT="https://teams.example/notify"), http(handler))
    assert (await h.send(note()))["status_code"] == 200
    assert seen["auth"] == "Bearer tk"
    assert seen["body"] == {
        "recipients": ["alice@corp.com", "@bob"], "subject": "Fix ready", "body": "Body text", "severity": "HIGH",
        "metadata": {"cve_id": "CVE-2024-35195", "event": "PR_RAISED", "pr_url": "https://pr", "cvss": 7.5},
    }  # fmt: skip
    assert not h.supports(note(recipients=[]))


async def test_teams_error_status_raises():
    h = TeamsHandler(cfg(TEAMS_API_KEY="tk"), http(lambda r: httpx.Response(500)))
    with pytest.raises(httpx.HTTPStatusError):
        await h.send(note())


async def test_webhook_is_signed_over_the_exact_body():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["sig"], seen["raw"] = req.headers["x-signature-256"], req.content
        return httpx.Response(204)

    h = WebhookHandler(cfg(WEBHOOK_URL="https://hook.example/x", WEBHOOK_SECRET="s3cret"), http(handler))
    await h.send(note())
    expected = "sha256=" + hmac.new(b"s3cret", seen["raw"], hashlib.sha256).hexdigest()
    assert seen["sig"] == expected == sign("s3cret", seen["raw"])
    payload = json.loads(seen["raw"])
    assert payload["event"] == "PR_RAISED" and payload["cve_id"] == "CVE-2024-35195" and payload["repo"] == "org/api"


async def test_webhook_only_when_configured():
    assert not WebhookHandler(cfg(), http(lambda r: httpx.Response(200))).supports(note())
    assert WebhookHandler(cfg(WEBHOOK_URL="https://x"), http(lambda r: httpx.Response(200))).supports(note())


class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout):
        self.host, self.port, self.sent, self.tls, self.login_args = host, port, [], False, None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        self.tls = True

    def login(self, user, password):
        self.login_args = (user, password)

    def send_message(self, msg):
        self.sent.append(msg)


async def test_email_sends_to_email_recipients_only_with_tls():
    FakeSMTP.instances.clear()
    c = cfg(SMTP_HOST="smtp.corp", SMTP_PORT=587, SMTP_USER="bot", SMTP_PASSWORD="pw", EMAIL_FROM="bot@corp.com")
    h = EmailHandler(c, smtp_factory=FakeSMTP)
    assert (await h.send(note(subject="Line1\nBcc: evil@x.com"))) == {"recipients": 1}
    (smtp,) = FakeSMTP.instances
    (msg,) = smtp.sent
    assert smtp.tls and smtp.login_args == ("bot", "pw") and (smtp.host, smtp.port) == ("smtp.corp", 587)
    assert msg["To"] == "alice@corp.com" and msg["From"] == "bot@corp.com"
    assert "\n" not in msg["Subject"] and msg["Bcc"] is None  # header injection neutralised


def test_email_supports_requires_config_and_recipients():
    assert not EmailHandler(cfg(), FakeSMTP).supports(note())
    c = cfg(SMTP_HOST="h", EMAIL_FROM="a@b.com")
    assert EmailHandler(c, FakeSMTP).supports(note()) and not EmailHandler(c, FakeSMTP).supports(note(recipients=["@bob"]))


async def test_pagerduty_only_pages_for_critical_escalations():
    h = PagerDutyHandler(cfg(PAGERDUTY_ROUTING_KEY="rk"), http(lambda r: httpx.Response(202)))
    assert not h.supports(note())  # PR_RAISED never pages
    assert not h.supports(note(event="ESCALATED", metadata={"cvss": 8.9}))
    assert h.supports(note(event="ESCALATED", metadata={"cvss": 9.0}))
    seen = {}

    def handler(req):
        seen.update(json.loads(req.content))
        return httpx.Response(202)

    h = PagerDutyHandler(cfg(PAGERDUTY_ROUTING_KEY="rk"), http(handler))
    await h.send(note(event="ESCALATED", metadata={"cvss": 9.8}))
    assert seen["routing_key"] == "rk" and seen["event_action"] == "trigger"
    assert seen["dedup_key"] == "cve-remediation:CVE-2024-35195:org/api" and seen["payload"]["severity"] == "critical"


# ------------------------------------------------------------------ dispatcher
def dispatcher(*handlers, idem=None):
    log = MemoryNotificationLog()
    return NotificationDispatcher(list(handlers), idem or MemoryIdempotency(), log), log


async def test_sends_once_per_job_event_channel():
    teams = RecordingHandler("teams")
    d, log = dispatcher(teams)
    first = await d.dispatch(note())
    second = await d.dispatch(note())  # e.g. checkpoint resume
    assert [r.status for r in first] == ["sent"] and [r.status for r in second] == ["skipped"]
    assert len(teams.sent) == 1
    assert log.rows == [("teams", "sent", "notify:job-1:PR_RAISED:teams"), ("teams", "skipped", "notify:job-1:PR_RAISED:teams")]


async def test_different_event_or_job_is_sent_again():
    teams = RecordingHandler("teams")
    d, _ = dispatcher(teams)
    await d.dispatch(note())
    await d.dispatch(note(event="PR_MERGED"))
    await d.dispatch(note(job_id="job-2"))
    assert len(teams.sent) == 3


async def test_one_failing_channel_does_not_stop_the_others_and_never_raises():
    bad, good = RecordingHandler("teams", fail_times=99), RecordingHandler("webhook")
    d, log = dispatcher(bad, good)
    results = await d.dispatch(note())
    assert {r.channel: r.status for r in results} == {"teams": "failed", "webhook": "sent"}
    assert bad.attempts == 4 and "ConnectionError" in results[0].error  # 1 try + 3 retries, then give up
    assert ("teams", "failed", "notify:job-1:PR_RAISED:teams") in log.rows


async def test_transient_failure_is_retried_and_then_marked_sent():
    flaky = RecordingHandler("teams", fail_times=2)
    d, _ = dispatcher(flaky)
    assert (await d.dispatch(note()))[0].status == "sent" and flaky.attempts == 3


async def test_failed_delivery_can_be_retried_by_a_later_dispatch():
    h = RecordingHandler("teams", fail_times=99)
    d, _ = dispatcher(h)
    assert (await d.dispatch(note()))[0].status == "failed"
    h.fail_times = 0
    assert (await d.dispatch(note()))[0].status == "sent"  # a failure is not recorded as delivered


async def test_unsupported_channels_are_not_called_or_logged():
    h = RecordingHandler("pagerduty", supported=False)
    d, log = dispatcher(h)
    assert await d.dispatch(note()) == [] and h.attempts == 0 and log.rows == []


async def test_log_store_failure_does_not_hide_the_result():
    class BrokenLog:
        async def record(self, *a):
            raise RuntimeError("db down")

    d = NotificationDispatcher([RecordingHandler("teams")], MemoryIdempotency(), BrokenLog())
    assert (await d.dispatch(note()))[0].status == "sent"


async def test_secrets_never_appear_in_failure_text():
    class Leaky(RecordingHandler):
        async def send(self, n):
            raise RuntimeError("auth failed with token=abcdef1234567890")

    d, _ = dispatcher(Leaky("teams"))
    (r,) = await d.dispatch(note())
    assert "abcdef1234567890" not in r.error


def test_build_handlers_from_settings():
    names = [h.name for h in build_handlers(cfg(ENABLED_NOTIFICATION_CHANNELS="teams, webhook,email,pagerduty,carrier-pigeon"))]
    assert names == ["teams", "webhook", "email", "pagerduty"]
