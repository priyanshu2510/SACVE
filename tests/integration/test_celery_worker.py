"""A real Celery worker process: broker wiring, routing and the matcher -> remediation hand-off."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import redis
from celery import Celery

from src.core.config import settings
from tests.integration.test_matcher_db import sbom_doc, seed_cve, seed_repo

pytestmark = [pytest.mark.celery, pytest.mark.redis, pytest.mark.db]
ROOT = Path(__file__).resolve().parents[2]
BASE = settings.REDIS_URL.rsplit("/", 1)[0]
BROKER, BACKEND = f"{BASE}/14", f"{BASE}/15"


@pytest.fixture
def broker():
    r = redis.Redis.from_url(BROKER)
    try:
        r.ping()
    except redis.RedisError:
        pytest.skip("Redis not reachable")
    r.flushdb()
    redis.Redis.from_url(BACKEND).flushdb()
    yield r
    r.flushdb()
    redis.Redis.from_url(BACKEND).flushdb()


@pytest.fixture
def client():
    return Celery("test-client", broker=BROKER, backend=BACKEND)


@pytest.fixture
def worker(broker, client, migrated_db):
    """A worker consuming only the scanning queue (nothing may execute fix-agent jobs here)."""
    env = {**os.environ, "CELERY_BROKER_URL": BROKER, "CELERY_RESULT_BACKEND": BACKEND, "DATABASE_URL": settings.DATABASE_URL,
           "AUTOMATION_ENABLED": "true", "PYTHONPATH": str(ROOT)}  # fmt: skip
    proc = subprocess.Popen(
        [sys.executable, "-m", "celery", "-A", "src.workers.celery_app", "worker", "-Q", "scanning", "-P", "solo", "--loglevel=WARNING"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )  # fmt: skip
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if client.send_task("ops.ping", queue="scanning").get(timeout=3) == "pong":
                break
        except Exception:
            if proc.poll() is not None:
                pytest.fail("worker exited early:\n" + proc.stdout.read().decode()[-2000:])
    else:
        proc.terminate()
        pytest.fail("worker did not become ready")
    yield proc
    proc.terminate()
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_worker_executes_tasks_from_the_broker(worker, client):
    assert client.send_task("ops.ping", queue="scanning").get(timeout=30) == "pong"


async def test_matcher_task_enqueues_fix_jobs_on_the_remediation_queue(worker, client, broker):
    await seed_cve("CVE-2024-35195", 5.6, "MEDIUM", "pip", "requests", ["< 2.32.0"], "2.32.0")
    await seed_repo("org/api", sbom_doc(("pypi", "requests", "2.31.0", "requirements.txt")))

    import asyncio

    summary = await asyncio.to_thread(lambda: client.send_task("scan.match_cves", args=[["CVE-2024-35195"]], queue="scanning").get(timeout=60))
    assert summary["created"] == 1 and summary["enqueued"] == 1

    assert broker.llen("remediation") == 1  # waiting for a remediation worker, which this test does not start
    message = json.loads(broker.lindex("remediation", 0))
    assert message["headers"]["task"] == "remediation.run_fix_agent"
    import base64

    args, _kwargs, _ = json.loads(base64.b64decode(message["body"]))
    job_id, state = args
    assert state["job_id"] == job_id and state["cve_id"] == "CVE-2024-35195" and state["target_version"] == "2.32.0"
    assert message["properties"]["delivery_info"]["routing_key"] == "remediation"


async def test_unknown_cve_scan_reports_not_found(worker, client):
    import asyncio

    # the CVE is not in any feed we can reach from the worker -> must not crash the worker
    result = await asyncio.to_thread(lambda: client.send_task("scan.match_cves", args=[["CVE-1999-0000"]], queue="scanning").get(timeout=60))
    assert result["created"] == 0 and result["cves"] == 0
