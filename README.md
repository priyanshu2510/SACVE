# CVE Auto-Remediation Platform

Detects CVEs, generates a dependency fix with an LLM inside a LangGraph agent, validates it in a sandbox, and raises a PR.
This repo currently contains **milestones 1-5**: foundation, the detection pipeline (CVE feed → triage → SBOM → matcher →
job queue, driven by Celery + beat) and the complete LangGraph fix agent, from context assembly to a pull request awaiting
human review, notifications and the audit trail. The agent graph:

```
assemble_context → assess_reachability → generate_fix → score_confidence → run_sandbox → run_pre_tests
  → apply_patch → resolve_dependencies → run_post_tests → run_security_scan → cleanup_sandbox
  → create_pr → notify_owners → write_audit
```

A patch that does not apply, a dependency conflict, a test regression or a CVE still present loops back to `generate_fix`
(up to `MAX_FIX_ATTEMPTS`) with the failure appended; the sandbox is reused. Exhausted attempts end `BLOCKED`.

## Setup

```bash
uv venv --python 3.12 .venv && source .venv/bin/activate   # uv is used only to fetch Python 3.12
pip install -r requirements-dev.txt
cp .env.example .env                                        # then fill in real values
docker compose up -d postgres redis minio
python -m scripts.init_local_storage                       # create the (versioned) S3 buckets in local MinIO
docker build -f docker/sandbox/python.Dockerfile -t cve-sandbox-python docker/sandbox   # sandbox image (git + grype + baked vuln DB)
alembic upgrade head                                        # app tables + LangGraph checkpoint tables
```

## Run

```bash
# workers (one per queue group is typical in prod)
celery -A src.workers.celery_app worker -Q scanning,notifications,audit -c 4 --loglevel=INFO
celery -A src.workers.celery_app worker -Q remediation -c 2 --loglevel=INFO      # runs the LangGraph fix agent + sandboxes
celery -A src.workers.celery_app beat --loglevel=INFO                             # 02:00 SBOMs, 06:00 CVE feed, 07:00 Confluence page, 2-hourly SLA check, weekly calibration
uvicorn src.api.main:app --host 0.0.0.0 --port 8000                                # Control API
```

```bash
pytest -q                                      # DB / Docker tests skip automatically if unavailable
python -m scripts.smoke_aggregate CVE-2024-21626   # live NVD + OSV fetch, stored in local Postgres
```

## Layout

- `src/core` config (Pydantic Settings), secrets (env / AWS Secrets Manager), logging, DB, secret redaction
- `src/models` SQLAlchemy models; `alembic/versions` migrations (`0002` owns the LangGraph checkpoint DDL)
- `src/services/cve_aggregator` NVD/OSV clients, normaliser, store
- `src/agent` LangGraph agent: `state`, `routing` (pure edge functions), `graph`, `runner`, `nodes/`
- `src/services/github/client.py` `GitHubContentSource` protocol (PyGithub today, GitHub MCP adapter later)

## Operational notes

- `AUTOMATION_ENABLED=false` is the global kill-switch: `run_fix_agent` returns `DISABLED` without doing anything.
- Outside `ENVIRONMENT=local`, LangGraph's `checkpointer.setup()` is disabled; run Alembic migrations instead.
- Secrets are read through `src/core/secrets.py`; set `SECRETS_BACKEND=aws` to load them from AWS Secrets Manager.

## Sandbox

Sandboxes are Docker containers: non-root, `cap_drop=ALL`, `no-new-privileges`, read-only root, size-limited tmpfs
workspace, 2 GB / 0.5 CPU / pids limits, and **no network** (`SANDBOX_NETWORK_MODE=none`). The repo is cloned on the host
(the token never enters the container). Dependency installs need `SANDBOX_NETWORK_MODE=registry-allowlist`: the container
then joins `SANDBOX_EGRESS_NETWORK`, which must be an *internal* Docker network whose only exit is an allowlisting proxy to
your package registry (infra you provision; sandboxes refuse a non-internal network). The grype DB is baked into the image,
so rebuild the image regularly (CI/daily) to keep it fresh. `MAX_CONCURRENT_SANDBOXES` is enforced per worker process.

## Pull requests, notifications, audit

- One PR per `{cve_id, repo}`: a single atomic commit (Git Data API) on `fix/cve-{CVE}-{repo}-{YYYYMMDD}`, labels
  (`PR_LABELS` + `severity:<level>`), and review requested from the CODEOWNERS of the changed files (repo admins as fallback).
  An open bot PR for the same CVE is never duplicated (`PR_EXISTS`). The bot never merges.
- LLM/CVE-derived text is sanitised before it enters the PR (HTML, `@mentions`, `#refs`, images).
- Channels (`ENABLED_NOTIFICATION_CHANNELS`): `teams`, `webhook` (HMAC `X-Signature-256`), `email`, `pagerduty`
  (escalations of CVSS >= 9 only). Each is sent once per `(job, event, channel)` and every attempt lands in `notification_log`.
  Set `OWNER_EMAIL_DOMAIN` to turn `@user` into `user@domain` for email/Teams recipients.
- `write_audit` flushes events and the job row in one transaction, idempotently. It is not routed to `handle_error`:
  if it fails, the checkpoint stays before it and the Celery retry resumes there without repeating the PR or notifications.

## Detection pipeline

`scan.sync_cves` (06:00 UTC) reads NVD changes since a persisted cursor, enriches each with OSV (package ranges and fixes follow OSV
aliases such as GHSA-…), and stores only CVEs that touch a supported ecosystem. `scan.regenerate_sboms` (02:00 UTC) syncs the org's
repos, filters them (allow/block lists, archived, `cve-exempt`), and fans out `scan.generate_sbom` (shallow clone → Syft → S3 +
PostgreSQL). After each SBOM or CVE batch the matcher evaluates version ranges (per-branch fixes respected), records
`cve_repo_impact`, and creates one job per `{cve, repo}` in priority order (KEV first, then CVSS), capped by
`MAX_NEW_JOBS_PER_RUN`. Jobs that are merged/blocked/in flight are never touched; failed ones are retried after a cool-down.
The fix agent runs under a per-repo Redis lock (no racing PRs). `notifications.sla_escalation` pages (CVSS ≥ 9) when a critical
CVE still has no PR after `SLA_ESCALATION_AFTER_HOURS`. Set `SANDBOX_SLOTS_BACKEND=redis` so `MAX_CONCURRENT_SANDBOXES` caps
sandboxes across all workers.

## Control API

All routes except `/api/v1/health` and the webhook need `X-API-Key` (fails closed when `API_KEY` is unset). Set
`CONTROL_API_IP_ALLOWLIST` (IPs / CIDRs of the TCP peer; list your proxy's range when behind one) and put mTLS in front for production.

| Route | Purpose |
|---|---|
| `POST /api/v1/scan/trigger` `{repo_names?}` · `POST /api/v1/scan/cve/{id}` | queue a full / single-CVE scan |
| `GET /api/v1/jobs` · `GET /api/v1/jobs/{id}` | list (status, repo, cve, date filters, paging) / detail with the audit trail |
| `GET /api/v1/jobs/{id}/graph-trace` | LangGraph checkpoint history: which node ran, what runs next, key (redacted) state |
| `DELETE /api/v1/jobs/{id}` | cancel a queued job |
| `PATCH /api/v1/jobs/{id}/pause` · `POST /api/v1/jobs/{id}/resume` | pause a running job between graph steps (its sandbox is released) / resume from the checkpoint |
| `GET /api/v1/cves` | detected CVEs with affected-repo counts, job states and an overall `fix_status` |
| `GET/PATCH /api/v1/config/repos` | runtime allow / block list override |
| `POST /api/v1/webhooks/github` | HMAC-verified: `push` → SBOM refresh, `pull_request` closed → outcome, advisories → CVE sync |

**Human feedback loop:** when a bot PR is closed the webhook records `MERGED_CLEAN` / `MERGED_EDITED` (extra commits were pushed) /
`CLOSED_UNMERGED` against the confidence score it was raised with. A rejected PR marks the job `BLOCKED` so it is never raised
again. Weekly, `audit.recalibrate_confidence` moves the HIGH/MEDIUM thresholds shown in PRs to where reviewers actually accept them
(needs 30 reviewed PRs; each tier is judged on its own band).

**JIRA / Confluence:** switched on by setting `JIRA_API_TOKEN` / `CONFLUENCE_API_TOKEN`. A Confluence page (and, for Critical/High, a
JIRA ticket) is created *before* the agent runs so the PR and notifications can link to them; both are refreshed after the audit
flush and when the PR is merged or rejected. Failures there are logged and never block remediation.
