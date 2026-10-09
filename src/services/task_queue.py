"""What the API (and webhooks) can ask the workers to do, behind an interface so tests need no broker."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class TaskQueue(Protocol):
    """Fire-and-forget commands to the Celery workers. Each returns the task id."""

    def sync_cves(self) -> str:
        """Fetch recent CVE changes and match them."""

    def regenerate_sboms(self, repo_names: list[str] | None) -> str:
        """Refresh SBOMs for all (or the named) repositories."""

    def generate_sbom(self, repo_name: str) -> str:
        """Refresh one repository's SBOM (and match it)."""

    def scan_cve(self, cve_id: str) -> str:
        """Fetch one CVE and match it across all repositories."""

    def enqueue_fix(self, job_id: str, initial_state: dict[str, Any]) -> str:
        """Run the fix agent for a job."""

    def sync_tracking(self, job_id: str) -> str:
        """Refresh the job's Confluence page and JIRA ticket."""


class CeleryTaskQueue:
    """Celery implementation (imports are lazy so the API starts without importing the whole worker)."""

    def sync_cves(self) -> str:
        """Queue ``scan.sync_cves``."""
        from src.workers.tasks.scan_tasks import sync_cves_task

        return sync_cves_task.apply_async(queue="scanning").id

    def regenerate_sboms(self, repo_names: list[str] | None) -> str:
        """Queue ``scan.regenerate_sboms``."""
        from src.workers.tasks.scan_tasks import regenerate_sboms_task

        return regenerate_sboms_task.apply_async(args=[repo_names], queue="scanning").id

    def generate_sbom(self, repo_name: str) -> str:
        """Queue ``scan.generate_sbom``."""
        from src.workers.tasks.scan_tasks import generate_sbom_task

        return generate_sbom_task.apply_async(args=[repo_name], queue="scanning").id

    def scan_cve(self, cve_id: str) -> str:
        """Queue ``scan.scan_cve``."""
        from src.workers.tasks.scan_tasks import scan_cve_task

        return scan_cve_task.apply_async(args=[cve_id], queue="scanning").id

    def enqueue_fix(self, job_id: str, initial_state: dict[str, Any]) -> str:
        """Queue ``remediation.run_fix_agent``."""
        from src.workers.tasks.remediation_tasks import run_fix_agent_task

        return run_fix_agent_task.apply_async(args=[job_id, initial_state], queue="remediation").id

    def sync_tracking(self, job_id: str) -> str:
        """Queue ``audit.sync_tracking``."""
        from src.workers.tasks.audit_tasks import sync_tracking_task

        return sync_tracking_task.apply_async(args=[job_id], queue="audit").id
