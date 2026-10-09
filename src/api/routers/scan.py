"""Scan triggers."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException

from src.api.dependencies import Authed, get_queue
from src.schemas.api import Accepted, ScanTrigger
from src.services.task_queue import TaskQueue

router = APIRouter(prefix="/api/v1/scan", tags=["scan"], dependencies=Authed)
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@router.post("/trigger", status_code=202, response_model=Accepted)
async def trigger_scan(body: ScanTrigger | None = None, queue: TaskQueue = Depends(get_queue)) -> Accepted:
    """Manual full scan: refresh the CVE feed and regenerate SBOMs (optionally only for ``repo_names``)."""
    repos = body.repo_names if body else None
    return Accepted(task_ids={"sync_cves": queue.sync_cves(), "regenerate_sboms": queue.regenerate_sboms(repos)})


@router.post("/cve/{cve_id}", status_code=202, response_model=Accepted)
async def scan_cve(cve_id: str, queue: TaskQueue = Depends(get_queue)) -> Accepted:
    """Scan one CVE across all repositories."""
    if not _CVE_ID.match(cve_id):
        raise HTTPException(422, "cve_id must look like CVE-YYYY-NNNN")
    return Accepted(task_ids={"scan_cve": queue.scan_cve(cve_id.upper())})
