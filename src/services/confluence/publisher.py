"""Confluence Cloud publisher: per-CVE audit pages and the daily run page."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog

from src.core.config import Settings, secret_value, settings as default_settings
from src.services.atlassian import AtlassianClient, AtlassianError

log = structlog.get_logger(__name__)
MAX_PAYLOAD_CHARS = 400


@dataclass(frozen=True)
class PageRef:
    """A published page."""

    id: str
    url: str
    title: str


def esc(value: Any) -> str:
    """HTML-escape any value for the Confluence storage format."""
    return html.escape(str(value), quote=True)


def table(headers: list[str], rows: list[list[Any]], raw_columns: frozenset[int] = frozenset()) -> str:
    """Render an HTML table; cells are escaped unless their column index is in ``raw_columns``."""
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell if i in raw_columns else esc(cell)}</td>" for i, cell in enumerate(row)) + "</tr>" for row in rows
    )
    return f"<table><tbody><tr>{head}</tr>{body}</tbody></table>"


def link(url: str | None, text: str | None = None) -> str:
    """An escaped hyperlink (or an em dash if there is no URL). Only http(s) URLs are linked."""
    if not url or not url.startswith(("http://", "https://")):
        return "—"
    return f'<a href="{esc(url)}">{esc(text or url)}</a>'


def event_summary(payload: dict[str, Any]) -> str:
    """One-line, length-capped rendering of an audit event payload."""
    text = json.dumps(payload, default=str, sort_keys=True)
    return text if len(text) <= MAX_PAYLOAD_CHARS else text[:MAX_PAYLOAD_CHARS] + "…"


def cve_page_title(cve_id: str, repo_name: str) -> str:
    """Unique per ``{cve, repo}`` (Confluence titles are unique within a space)."""
    return f"{cve_id} remediation: {repo_name}"


def render_cve_page(job: dict[str, Any], events: list[dict[str, Any]]) -> str:
    """Per-CVE page body: summary table plus the full audit timeline."""
    rows_html = "".join(
        f"<tr><th>{esc(k)}</th><td>{v}</td></tr>"
        for k, v in [
            ("CVE", link(f"https://nvd.nist.gov/vuln/detail/{job['cve_id']}", job["cve_id"])),
            ("Severity / CVSS", esc(f"{job.get('severity') or '?'} / {job.get('cvss') if job.get('cvss') is not None else '?'}")),
            ("Repository", esc(job["repo_name"])),
            ("Package", esc(f"{job['affected_package']} {job['installed_version']} → {job['target_version']}")),
            ("Status", esc(job["status"])),
            ("Confidence", esc(f"{job['confidence_score']} / 100" if job.get("confidence_score") is not None else "—")),
            ("Fix attempts", esc(job.get("attempt_count", 0))),
            ("Pull request", link(job.get("pr_url"))),
            ("JIRA", esc(job["jira_issue_key"]) if job.get("jira_issue_key") else "—"),
            ("Job ID", esc(job["job_id"])),
        ]
    )
    timeline = table(
        ["Time (UTC)", "Event", "Details"],
        [[e["ts"], e["event_type"], event_summary(e.get("payload", {}))] for e in events],
    )
    return f"<h2>Summary</h2><table><tbody>{rows_html}</tbody></table><h2>Audit timeline</h2>{timeline}"


def daily_page_title(day: datetime) -> str:
    """Title of the daily run page."""
    return f"CVE Remediation Daily Run – {day:%Y-%m-%d}"


def render_daily_page(day: datetime, stats: dict[str, Any], jobs: list[dict[str, Any]]) -> str:
    """Daily run page: counts, status summary and the jobs created in the last 24 hours."""
    status_rows = [[k, v] for k, v in sorted(stats.get("by_status", {}).items())]
    job_rows = [
        [j["cve_id"], j["repo_name"], j["status"], link(j.get("pr_url")), esc(j["jira_issue_key"]) if j.get("jira_issue_key") else "—"]
        for j in jobs
    ]
    jobs_table = (
        "<table><tbody><tr><th>CVE</th><th>Repository</th><th>Status</th><th>PR</th><th>JIRA</th></tr>"
        + "".join(f"<tr><td>{esc(r[0])}</td><td>{esc(r[1])}</td><td>{esc(r[2])}</td><td>{r[3]}</td><td>{r[4]}</td></tr>" for r in job_rows)
        + "</tbody></table>"
    )
    return (
        f"<h2>Run summary for {esc(f'{day:%Y-%m-%d}')}</h2>"
        + table(["Metric", "Count"], [["CVEs added or updated", stats.get("cves", 0)], ["Repositories affected", stats.get("repos", 0)],
                                      ["Jobs created", stats.get("jobs", 0)]])  # fmt: skip
        + "<h2>Jobs by status</h2>" + table(["Status", "Jobs"], status_rows)
        + "<h2>Jobs created</h2>" + jobs_table
    )


class ConfluencePublisher:
    """Creates and updates pages in the configured space (idempotent by title)."""

    def __init__(self, cfg: Settings | None = None, client: AtlassianClient | None = None) -> None:
        self._cfg = cfg or default_settings
        self._client = client or AtlassianClient(
            self._cfg.CONFLUENCE_BASE_URL, self._cfg.CONFLUENCE_USER, secret_value(self._cfg.CONFLUENCE_API_TOKEN, "CONFLUENCE_API_TOKEN")
        )

    def _ref(self, data: dict[str, Any]) -> PageRef:
        links = data.get("_links", {})
        base = links.get("base") or f"{self._cfg.CONFLUENCE_BASE_URL.rstrip('/')}/wiki"
        return PageRef(str(data["id"]), f"{base}{links.get('webui', '')}", data.get("title", ""))

    async def find_page(self, title: str) -> dict[str, Any] | None:
        """The page with exactly this ``title`` in the space, or ``None``."""
        data = await self._client.request(
            "GET", "/wiki/rest/api/content",
            params={"title": title, "spaceKey": self._cfg.CONFLUENCE_SPACE_KEY, "expand": "version", "type": "page"},
        )  # fmt: skip
        results = (data or {}).get("results", [])
        return results[0] if results else None

    async def upsert_page(self, title: str, body_html: str) -> PageRef:
        """Create the page under the configured parent, or update it if the title already exists."""
        existing = await self.find_page(title)
        if existing is None:
            try:
                data = await self._client.request(
                    "POST", "/wiki/rest/api/content",
                    json={
                        "type": "page", "title": title, "space": {"key": self._cfg.CONFLUENCE_SPACE_KEY},
                        "ancestors": [{"id": self._cfg.CONFLUENCE_PARENT_PAGE_ID}],
                        "body": {"storage": {"value": body_html, "representation": "storage"}},
                    },
                )  # fmt: skip
                return self._ref(data)
            except AtlassianError as exc:
                if exc.status != 400 or "already exists" not in exc.message.lower():
                    raise
                existing = await self.find_page(title)  # lost a creation race
                if existing is None:
                    raise
        data = await self._client.request(
            "PUT", f"/wiki/rest/api/content/{existing['id']}",
            json={
                "type": "page", "title": title, "version": {"number": existing["version"]["number"] + 1},
                "body": {"storage": {"value": body_html, "representation": "storage"}},
            },
        )  # fmt: skip
        return self._ref(data)

    async def publish_cve_page(self, job: dict[str, Any], events: list[dict[str, Any]]) -> PageRef:
        """Create/update the per-CVE audit page."""
        return await self.upsert_page(cve_page_title(job["cve_id"], job["repo_name"]), render_cve_page(job, events))

    async def publish_daily_page(self, day: datetime, stats: dict[str, Any], jobs: list[dict[str, Any]]) -> PageRef:
        """Create/update the daily run page."""
        return await self.upsert_page(daily_page_title(day), render_daily_page(day, stats, jobs))
