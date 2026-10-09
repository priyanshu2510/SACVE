"""JIRA Cloud issue creator: one ticket per Critical/High CVE job, kept in sync with the job."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from src.core.config import Settings, secret_value, settings as default_settings
from src.services.atlassian import AtlassianClient, AtlassianError
from src.services.triage.prioritiser import JIRA_PRIORITY, PRIORITY_BY_SEVERITY

log = structlog.get_logger(__name__)

OPTIONAL_FIELDS = {"priority", "assignee", "labels"}  # a project may not expose these: drop and retry rather than fail


@dataclass
class TicketContext:
    """Everything the ticket is built from."""

    job_id: str
    cve_id: str
    severity: str
    cvss: float | None
    repo_name: str
    package: str
    installed_version: str
    target_version: str
    status: str
    pr_url: str | None = None
    confluence_url: str | None = None
    owner_emails: list[str] = field(default_factory=list)
    issue_key: str | None = None


# ----------------------------------------------------------------------------- Atlassian Document Format
def _text(text: str, href: str | None = None) -> dict[str, Any]:
    node: dict[str, Any] = {"type": "text", "text": text}
    if href and href.startswith(("http://", "https://")):
        node["marks"] = [{"type": "link", "attrs": {"href": href}}]
    return node


def _para(*nodes: dict[str, Any]) -> dict[str, Any]:
    return {"type": "paragraph", "content": list(nodes)}


def adf(*paragraphs: dict[str, Any]) -> dict[str, Any]:
    """An ADF document (JIRA v3 rejects plain-string descriptions)."""
    return {"type": "doc", "version": 1, "content": list(paragraphs)}


def description(ctx: TicketContext) -> dict[str, Any]:
    """Ticket description: what, where, and links to the PR and the audit page when they exist."""
    paras = [
        _para(_text("Automatically raised by the CVE Auto-Remediation Platform.")),
        _para(_text("CVE: "), _text(ctx.cve_id, f"https://nvd.nist.gov/vuln/detail/{ctx.cve_id}"),
              _text(f" ({ctx.severity}, CVSS {ctx.cvss if ctx.cvss is not None else '?'})")),  # fmt: skip
        _para(_text(f"Repository: {ctx.repo_name}")),
        _para(_text(f"Fix: {ctx.package} {ctx.installed_version} → {ctx.target_version}")),
        _para(_text(f"Job status: {ctx.status}")),
    ]
    if ctx.pr_url:
        paras.append(_para(_text("Pull request: "), _text(ctx.pr_url, ctx.pr_url)))
    if ctx.confluence_url:
        paras.append(_para(_text("Audit trail: "), _text(ctx.confluence_url, ctx.confluence_url)))
    return adf(*paras)


def summary(ctx: TicketContext) -> str:
    """Single-line summary (JIRA limit is 255 chars)."""
    short = ctx.repo_name.split("/")[-1]
    text = f"[{ctx.cve_id}] {ctx.severity}: bump {ctx.package} {ctx.installed_version} → {ctx.target_version} in {short}"
    return " ".join(text.split())[:250]


def job_label(job_id: str) -> str:
    """Label used to find a job's ticket again (idempotent creation)."""
    return f"cve-job-{job_id}"


class JiraIssueCreator:
    """Create, find, update and transition JIRA issues."""

    def __init__(self, cfg: Settings | None = None, client: AtlassianClient | None = None) -> None:
        self._cfg = cfg or default_settings
        self._client = client or AtlassianClient(
            self._cfg.JIRA_BASE_URL, self._cfg.JIRA_USER, secret_value(self._cfg.JIRA_API_TOKEN, "JIRA_API_TOKEN")
        )

    def wants(self, severity: str) -> bool:
        """Only Critical and High CVEs get tickets (``JIRA_SEVERITIES``)."""
        return severity.upper() in {s.upper() for s in self._cfg.JIRA_SEVERITIES}

    def issue_url(self, key: str) -> str:
        """Browse URL of an issue."""
        return f"{self._cfg.JIRA_BASE_URL.rstrip('/')}/browse/{key}"

    # -- lookups -----------------------------------------------------------------------------
    async def find_by_job(self, job_id: str) -> str | None:
        """Key of the existing ticket for this job (survives a crash between create and persist)."""
        data = await self._client.request(
            "POST", "/rest/api/3/search/jql",
            json={"jql": f'project = "{self._cfg.JIRA_PROJECT_KEY}" AND labels = "{job_label(job_id)}"', "fields": ["key"], "maxResults": 1},
        )  # fmt: skip
        issues = (data or {}).get("issues", [])
        return issues[0]["key"] if issues else None

    async def account_id(self, email: str) -> str | None:
        """JIRA accountId for an email address (users may hide their email, so this can be ``None``)."""
        users = await self._client.request("GET", "/rest/api/3/user/search", params={"query": email})
        for user in users or []:
            if user.get("accountType", "atlassian") == "atlassian" and user.get("accountId"):
                return user["accountId"]
        return None

    # -- writes ------------------------------------------------------------------------------
    async def create_issue(self, ctx: TicketContext) -> str:
        """Create the ticket (or return the existing one for this job)."""
        existing = await self.find_by_job(ctx.job_id)
        if existing:
            return existing
        priority = JIRA_PRIORITY.get(PRIORITY_BY_SEVERITY.get(ctx.severity.upper(), "P3"), "P3 - Medium")
        fields: dict[str, Any] = {
            "project": {"key": self._cfg.JIRA_PROJECT_KEY},
            "issuetype": {"name": self._cfg.JIRA_ISSUE_TYPE},
            "summary": summary(ctx),
            "description": description(ctx),
            "priority": {"name": priority},
            "labels": ["security", "cve-fix", "automated", job_label(ctx.job_id)],
        }
        for email in ctx.owner_emails:
            if account := await self.account_id(email):
                fields["assignee"] = {"accountId": account}
                break
        try:
            data = await self._client.request("POST", "/rest/api/3/issue", json={"fields": fields})
        except AtlassianError as exc:
            rejected = {name for name in OPTIONAL_FIELDS if name in fields and name in exc.message}
            if exc.status != 400 or not rejected:
                raise
            log.warning("jira.optional_fields_rejected", fields=sorted(rejected), error=exc.message)
            data = await self._client.request(
                "POST", "/rest/api/3/issue", json={"fields": {k: v for k, v in fields.items() if k not in rejected}}
            )
        return data["key"]

    async def assign(self, key: str, email: str) -> bool:
        """Assign the issue to the user with this email; ``False`` if no such JIRA user is visible."""
        account = await self.account_id(email)
        if account is None:
            return False
        await self._client.request("PUT", f"/rest/api/3/issue/{key}/assignee", json={"accountId": account}, ok=(200, 204))
        return True

    async def update_description(self, key: str, ctx: TicketContext) -> None:
        """Refresh the description (PR / Confluence links appear after creation)."""
        await self._client.request("PUT", f"/rest/api/3/issue/{key}", json={"fields": {"description": description(ctx)}}, ok=(200, 204))

    async def comment(self, key: str, text: str, href: str | None = None) -> None:
        """Add a comment."""
        await self._client.request("POST", f"/rest/api/3/issue/{key}/comment", json={"body": adf(_para(_text(text, href)))})

    async def current_status(self, key: str) -> str | None:
        """Name of the issue's current status."""
        data = await self._client.request("GET", f"/rest/api/3/issue/{key}", params={"fields": "status"})
        return ((data or {}).get("fields", {}).get("status") or {}).get("name")

    async def transition_to(self, key: str, target: str) -> bool:
        """Move the issue to ``target`` (matched against transition and destination names); ``False`` if impossible."""
        if (await self.current_status(key) or "").lower() == target.lower():
            return True
        data = await self._client.request("GET", f"/rest/api/3/issue/{key}/transitions")
        wanted = target.lower()
        for t in (data or {}).get("transitions", []):
            if wanted in (t.get("name", "").lower(), (t.get("to") or {}).get("name", "").lower()):
                await self._client.request("POST", f"/rest/api/3/issue/{key}/transitions", json={"transition": {"id": t["id"]}}, ok=(200, 204))
                return True
        log.warning("jira.transition_unavailable", issue=key, target=target)
        return False

    async def sync_status(self, ctx: TicketContext) -> bool:
        """Apply ``JIRA_STATUS_TRANSITIONS`` for the job's status. No mapping means no change."""
        target = self._cfg.JIRA_STATUS_TRANSITIONS.get(ctx.status)
        if target is None or ctx.issue_key is None:
            return False
        return await self.transition_to(ctx.issue_key, target)
