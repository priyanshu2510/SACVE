"""Hand-over content, part 2: detection pipeline, services, workers, API, data model, configuration."""

from __future__ import annotations

from typing import Any

from scripts import handover_diagrams as DG
from scripts.handover_lib import callout, chip, code, esc, pre, section, table, ul


def pipeline(f: dict[str, Any]) -> str:
    policy = [
        ["no job yet", "create", "A new <code>QUEUED</code> job and a queue message."],
        ["<code>MERGED</code> · <code>BLOCKED</code> · <code>NOT_REACHABLE</code> · <code>CANCELLED</code>", "skip", "Finished, or a human decided. Never touched again."],
        ["<code>QUEUED</code> · <code>RUNNING</code> · <code>PR_RAISED</code> · <code>PAUSED</code> · …", "skip", "In flight, or waiting for review."],
        ["<code>FAILED</code> and older than <code>FAILED_JOB_RETRY_AFTER_HOURS</code> (24)", "re-queue", "Same job row, new <code>run_id</code>. Failures are usually transient (LLM, GitHub, Docker)."],
        ["<code>QUEUED</code> for more than 6 hours", "re-queue", "The broker message was lost; recover it."],
    ]
    return section("detection", "Detection pipeline", f"""
{DG.detection()}
<h3>1 · CVE feed <span class="muted">src/services/cve_aggregator/, src/services/pipeline.py</span></h3>
{ul([
    "<code>sync_cves</code> reads NVD CVEs <i>modified</i> since the cursor stored in <code>sync_state['cve_sync']</code> (first run: last 24 hours; each run re-reads 10 minutes before the cursor; windows are split at 119 days because NVD refuses more than 120).",
    "Each CVE is merged with OSV. <b>OSV's CVE record usually only has git ranges.</b> The package versions and fixes are on its aliases (<code>GHSA-…</code>, <code>GO-…</code>, <code>PYSEC-…</code>), which the aggregator fetches and merges. NVD is authoritative for CVSS and KEV, OSV for affected ranges and fixes.",
    "A CVE is stored only if it has an affected package in one of the six supported ecosystems (npm, pip, maven, go, nuget, gem). CVEs that fail to process are remembered in the cursor's <code>retry_ids</code> and fetched again next run.",
    "NVD allows 5 requests per 30 seconds without an API key and 50 with one. Set <code>NVD_API_KEY</code> in production.",
])}
<h3>2 · Triage <span class="muted">src/services/triage/prioritiser.py</span></h3>
<p>Priority from CVSS v3 (Critical ≥ 9, High ≥ 7, Medium ≥ 4, Low), ranked KEV first, then score, then age. CVEs below <code>MIN_CVSS_THRESHOLD</code> or without a score are dropped (they return on a later sync once NVD scores them), <b>except KEV CVEs, which are always kept</b>.</p>
<h3>3 · SBOM <span class="muted">src/services/sbom/generator.py</span></h3>
{ul([
    "Shallow clone on the host, <code>syft dir:… -o cyclonedx-json</code>, archive the document to <code>s3://$S3_BUCKET_SBOM/{repo}/{commit}.cdx.json</code>, and keep a row per generation in <code>sboms</code> (history is kept; the newest row is current).",
    "Only <b>remediable</b> components are kept: supported ecosystem, an <i>exact</i> version (<code>flask&gt;=2.0</code> is ignored) and declared in a file a PR can edit. A manifest wins over a lockfile. Packages seen only as installed metadata are ignored.",
    "Syft must be on the worker's <code>PATH</code> (or <code>SYFT_BIN</code>). A pinned, checksum-verified copy for local use lives in <code>.tools/</code> (git-ignored).",
])}
<h3>4 · Matcher <span class="muted">src/services/matcher/vulnerability_matcher.py</span></h3>
{ul([
    "Ranges come from OSV as strings such as <code>&lt; 1.4.9</code>, <code>&gt;= 2.0.0, &lt; 2.0.3</code>, <code>&lt;= 3.1.0</code>, <code>all versions</code>.",
    "The <b>safe version</b> is the smallest known fix that clears every range containing the installed version, so 2.0.1 goes to 2.0.3, not down to 1.4.9. If no usable fix exists the match is counted (<code>no_fix</code>) and no job is created.",
    "Package names are compared after normalisation (PEP 503 for pip, lower-case elsewhere), so <code>Jinja2</code> matches <code>jinja2</code>.",
    "One job per <code>{cve, repo}</code> pair (unique constraint <code>uq_job_cve_repo</code>). Jobs are created most urgent first and capped by <code>MAX_NEW_JOBS_PER_RUN</code> (50) to protect LLM spend; the rest wait for the next run.",
    "Impacts no longer present in a repo's newest SBOM are deleted on a full run. Messages are sent <b>after</b> the database commit so a worker never sees a job that is not there yet.",
    "The full agent input is stored in the <code>JOB_QUEUED</code> audit event; the Control API uses it to resume a paused job.",
])}
{table(["Existing job", "Action", "Why"], policy, compact=True)}
<h3>5 · Repo scope <span class="muted">src/services/matcher/repo_filter.py, src/services/github/repos.py</span></h3>
<p>The organisation's repos are synced into <code>repos</code> daily. A repo is in scope unless it is archived, has the <code>cve-exempt</code> topic, is on the blocklist, or is missing from a non-empty allowlist (blocklist wins). Lists come from <code>config/repos.yaml</code> plus <code>REPO_ALLOWLIST</code>/<code>REPO_BLOCKLIST</code>; a runtime override set through <code>PATCH /api/v1/config/repos</code> (stored in <code>sync_state['repo_filter_override']</code>) replaces both.</p>""")


def services() -> str:
    sandbox = [
        ["Runs as", "uid 1000, <code>init</code> enabled"], ["Capabilities", "<code>cap_drop=ALL</code>, <code>no-new-privileges</code>"],
        ["Filesystem", "read-only root; size-limited tmpfs for <code>/workspace</code> (512m), <code>/opt/venv</code> (768m), <code>/tmp</code> (128m)"],
        ["Resources", "2 GB RAM with no swap, 0.5 CPU, 256 pids, per-command timeout (<code>SANDBOX_TIMEOUT_SECONDS</code> 600)"],
        ["Network", "<code>none</code> by default. <code>registry-allowlist</code> joins an <b>internal</b> Docker network whose only exit is an allowlisting proxy to your package registry. The manager refuses a network that is not internal unless <code>SANDBOX_ALLOW_NON_INTERNAL_NETWORK</code> is set (local development only)."],
        ["Mounts", "no Docker socket, no host bind mounts"], ["Secrets", "the repo is cloned on the host and copied in; the GitHub token never enters the container"],
    ]
    channels = [
        ["teams", "<code>POST TEAMS_API_ENDPOINT</code> with <code>Authorization: Bearer</code>. <b>Payload and auth are my assumption</b> of your internal API.", "needs recipients"],
        ["webhook", "<code>POST WEBHOOK_URL</code>, header <code>X-Signature-256: sha256=HMAC(body)</code> (the GitHub scheme).", "needs a URL"],
        ["email", "SMTP with STARTTLS, only to real email addresses; subject newlines are stripped.", "needs SMTP_HOST, EMAIL_FROM"],
        ["pagerduty", "Events API v2 trigger, <code>dedup_key</code> per CVE and repo.", "only ESCALATED events with CVSS ≥ 9"],
    ]
    return section("services", "Services", f"""
<h3>Sandbox <span class="muted">src/services/sandbox/</span></h3>
{DG.sandbox()}
{table(["Control", "Setting"], sandbox, compact=True)}
{ul([
    "<b>Image:</b> <code>docker/sandbox/python.Dockerfile</code> is <code>python:3.12-slim</code> plus git and a checksum-verified Grype whose vulnerability database is baked in (about 4.2 GB). The scanner runs with database updates off, so <b>rebuild the image regularly</b>; a stale image silently misses new CVEs.",
    "<b>Files go in as a tar stream through <code>exec</code></b>. Docker's <code>put_archive</code> is refused on read-only root filesystems.",
    "<b>Concurrency:</b> <code>MAX_CONCURRENT_SANDBOXES</code> is enforced per process by default. Set <code>SANDBOX_SLOTS_BACKEND=redis</code> to share one cap across all workers (leases expire after 6 hours so a crashed worker cannot leak slots).",
    "Containers carry labels (<code>cve-remediation.sandbox</code>, <code>cve-remediation.job_id</code>). Creating a sandbox first removes stale ones for the same job.",
])}
<h3>GitHub and pull requests <span class="muted">src/services/github/</span></h3>
{ul([
    "<code>PyGithubContentSource</code> reads files, code search and release notes (via the package's upstream repo, resolved from PyPI, npm or the Go module path). <code>PyGithubPullRequestService</code> writes.",
    "A PR is <b>one atomic commit</b> through the Git Data API (blobs, tree, commit, ref), based on the default branch's current head with the validated section replacements re-applied. If the base moved so the section no longer matches exactly once, the job fails instead of committing something untested.",
    "Branch <code>fix/cve-{CVE}-{repo}-{YYYYMMDD}</code> (a numeric suffix if taken). Labels from <code>PR_LABELS</code> plus <code>severity:&lt;level&gt;</code>, created if missing. Reviewers: owners of the changed files from CODEOWNERS (<code>.github/CODEOWNERS</code>, <code>CODEOWNERS</code>, <code>docs/CODEOWNERS</code>; last matching rule wins), falling back to repo admins. An invalid reviewer is a warning, not a failure.",
    "<b>Dedup guard:</b> an open PR whose branch starts with the bot prefix for the same CVE is reused or skipped. A hidden marker <code>&lt;!-- cve-remediation-bot job_id=… --&gt;</code> in the body ties a PR to its job. A failed PR creation deletes the branch it pushed.",
    "Text from the model or the CVE is sanitised before it enters the PR body (HTML, <code>@mentions</code>, <code>#123</code> references and image embeds are neutralised).",
    "<b>Branch protection is reported, not enforced:</b> the bot cannot merge, but protection and required CODEOWNERS review must be configured on the target repos by you.",
    "PyGithub paces itself (<code>GITHUB_SECONDS_BETWEEN_REQUESTS</code> 0.25 s, <code>…_WRITES</code> 1 s), so a PR takes about ten seconds. Rate limits and 5xx are retried with backoff.",
])}
<h3>Notifications <span class="muted">src/services/notifications/</span></h3>
<p>Each channel implements <code>NotificationHandler</code> (<code>supports()</code>, <code>send()</code>). The dispatcher sends once per <code>(job, event, channel)</code>, retries transient errors three times, never raises, and logs every attempt to <code>notification_log</code>. Events: <code>CVE_DETECTED</code>, <code>PR_RAISED</code> (sent today), <code>PR_MERGED</code> (sent from the webhook), <code>ESCALATED</code> (SLA task). A <code>@user</code> owner becomes <code>user@OWNER_EMAIL_DOMAIN</code> when that is set; teams stay <code>@org/team</code>.</p>
{table(["Channel", "How it works", "Active when"], channels, compact=True)}
<h3>Confluence and JIRA <span class="muted">src/services/confluence/, src/services/jira/, src/services/tracking.py</span></h3>
{ul([
    "Both are on only when their API token is set. Failures are logged and <b>never block remediation</b>.",
    "<b><code>TrackingService.ensure</code> runs before the agent</b> so the PR body and notifications can link to the ticket and page. After <code>write_audit</code> the <code>audit.sync_tracking</code> task refreshes the Confluence page (summary and full timeline), the JIRA description, assignee (first CODEOWNER email), a PR comment (once) and the status.",
    "Confluence: REST v1, storage-format HTML with every value escaped. The page title <code>{CVE} remediation: {repo}</code> is the idempotency key (create, or update with version + 1).",
    "JIRA: REST v3 with Atlassian Document Format descriptions. A ticket is found again by the label <code>cve-job-{job_id}</code> using <code>POST /rest/api/3/search/jql</code>. Only <code>JIRA_SEVERITIES</code> (Critical, High) get tickets. Priority names come from the spec (<code>P1 - Critical</code> …); if the project does not expose priority or assignee, those fields are dropped and the ticket is still created.",
    "Status changes use <code>JIRA_STATUS_TRANSITIONS</code> (job status → JIRA status name, matched against transition and destination names). Your workflow's names must match.",
])}
<h3>Confidence calibration <span class="muted">src/services/calibration.py, src/services/pr_outcomes.py</span></h3>
{DG.feedback()}
<p>The <code>pull_request closed</code> webhook records <code>MERGED_CLEAN</code>, <code>MERGED_EDITED</code> (more than one commit, so a human added to the branch) or <code>CLOSED_UNMERGED</code> in <code>pr_outcomes</code> next to the score the PR was raised with. A closed-unmerged PR marks the job <code>BLOCKED</code> so it is never raised again. A PR is attributed to a job only if the branch prefix, the body marker, the repository <i>and</i> the PR number all match (a pasted marker alone is not trusted). Weekly, <code>audit.recalibrate_confidence</code> moves the HIGH and MEDIUM cut-offs to the lowest scores whose own band was merged clean at least 90% and 70% of the time. It needs 30 reviewed PRs and 10 per band, and keeps the defaults otherwise.</p>""")


def workers(f: dict[str, Any]) -> str:
    task_rows = [[code(t["name"]), code(t["queue"]), esc(t["doc"])] for t in f["tasks"]]
    beat_rows = [[code(b["entry"]), code(b["task"]), esc(b["schedule"])] for b in f["beat"]]
    return section("workers", "Workers and scheduling", f"""
<p>Defined in <code>src/workers/</code>. Celery tasks are thin: they call async functions through <code>run_async</code>, which runs a fresh event loop per task and then disposes the database engine and the lazily built dependencies (asyncpg connections and HTTP clients cannot be shared across loops).</p>
<h3>Tasks <span class="muted">(generated)</span></h3>
{table(["Task", "Queue", "Purpose"], task_rows, compact=True)}
<h3>Beat schedule <span class="muted">(generated, UTC)</span></h3>
{table(["Entry", "Task", "Schedule"], beat_rows, compact=True)}
<h3>The remediation task</h3>
{ul([
    "<b>Lock first, then claim.</b> It takes <code>cve-remediation:repo-lock:&lt;repo&gt;</code> (TTL 3 h) so two jobs never race PRs on one repo, then atomically moves the job <code>QUEUED→RUNNING</code>. A duplicate or redelivered message finds the job not queued and exits.",
    "<b>Lock busy:</b> retry in 5 minutes, up to 36 times. This does not use up the failure budget.",
    "<b>Failure:</b> up to 3 retries with exponential backoff. Because the graph is checkpointed, a retry resumes at the failed step and never repeats a finished PR or LLM call. After the last retry the job is marked FAILED instead of staying RUNNING.",
    "Soft time limit 3 h, hard limit 3 h 10 min. The Redis <code>visibility_timeout</code> is 4 h, which must stay above the hard limit, otherwise Redis redelivers a still-running task.",
    "<code>AUTOMATION_ENABLED=false</code> makes the task skip the job (it stays <code>QUEUED</code>) and the matcher skip creating jobs.",
])}
<h3>Running</h3>
{pre("celery -A src.workers.celery_app worker -Q scanning,notifications,audit -c 4 --loglevel=INFO\ncelery -A src.workers.celery_app worker -Q remediation -c 2 --loglevel=INFO\ncelery -A src.workers.celery_app beat --loglevel=INFO\nuvicorn src.api.main:app --host 0.0.0.0 --port 8000")}
<p>Run the remediation queue on its own workers: each job holds a Docker sandbox for minutes, and the other queues should not wait behind them.</p>""")


def api(f: dict[str, Any]) -> str:
    rows = [[code(r["method"]), code(r["path"]), esc(r["summary"])] for r in f["routes"]]
    hooks = [
        ["<code>ping</code>", "Answers pong."],
        ["<code>push</code> to the default branch", "Queues <code>scan.generate_sbom</code> for the repo if it is in scope."],
        ["<code>pull_request</code> action <code>closed</code>", "Records the outcome, sets the job MERGED or BLOCKED, sends a <code>PR_MERGED</code> notification when merged, queues a JIRA/Confluence refresh."],
        ["<code>security_advisory</code> / <code>repository_advisory</code> published or updated", "Queues <code>scan.sync_cves</code>."],
        ["anything else", "Acknowledged and ignored."],
    ]
    return section("api", "Control API", f"""
<p><code>src/api/</code>. Run with <code>uvicorn src.api.main:app</code>. The interactive docs are at <code>/api/docs</code> everywhere except <code>ENVIRONMENT=prod</code>.</p>
<h3>Routes <span class="muted">(generated)</span></h3>
{table(["Method", "Path", "Summary"], rows, compact=True)}
<h3>Access control</h3>
{ul([
    "<b>API key:</b> header <code>X-API-Key</code>, compared in constant time. If <code>API_KEY</code> is unset every protected route answers 503 (it fails closed).",
    "<b>IP allowlist:</b> <code>CONTROL_API_IP_ALLOWLIST</code> takes IPs or CIDRs and checks the TCP peer. Behind a proxy, list the proxy's range. It applies to the webhook too, so include GitHub's hook ranges or front it with a proxy. <code>/health</code> is exempt so orchestrator probes work.",
    "<b>Webhook:</b> not API-key protected (GitHub cannot send one). It verifies <code>X-Hub-Signature-256</code> over the exact request bytes, fails closed without <code>GITHUB_WEBHOOK_SECRET</code>, caps the body at 5 MB, and ignores a repeated <code>X-GitHub-Delivery</code> id.",
])}
{table(["GitHub event", "Effect"], hooks, compact=True)}
<h3>Job control rules</h3>
{ul([
    "<b>Cancel</b> (<code>DELETE</code>) works only on <code>QUEUED</code> jobs; the queued worker message then finds the job cancelled and exits.",
    "<b>Pause</b> works only on <code>RUNNING</code> jobs. <b>Resume</b> works only on <code>PAUSED</code> jobs that have a recorded initial state. Anything else answers 409 with the current status. Each action writes an audit event.",
    "<b>Graph trace</b> returns, oldest first, the node that ran, the node that runs next and an allow-listed, redacted slice of the state (never prompts, source or file contents).",
])}
{pre('curl -s -H "X-API-Key: $API_KEY" "http://localhost:8000/api/v1/jobs?status=BLOCKED&limit=20"\ncurl -s -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/jobs/$JOB_ID/graph-trace\ncurl -s -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/scan/cve/CVE-2024-35195')}""")


TABLE_PURPOSE = {
    "cves": "Normalised CVE (CVSS, severity, KEV, raw NVD/OSV data)", "cve_affected_packages": "Affected package per CVE: ecosystem, range strings, lowest fix",
    "cve_raw_feeds": "Append-only copy of each raw feed response", "repos": "GitHub repositories (default branch, archived, topics)",
    "remediation_jobs": "One job per CVE and repo; also the LangGraph thread id", "cve_repo_impact": "Which repos a CVE affects, installed vs safe version, manifest",
    "audit_events": "Append-only event trail (a trigger rejects UPDATE and DELETE)", "pr_outcomes": "How each bot PR ended, with the predicted confidence",
    "sboms": "SBOM documents, one row per generation", "notification_log": "Every notification attempt, successful or not",
    "idempotency_keys": "Check-before-create guard for PRs, notifications, audit, webhooks", "sync_state": "Cursors and runtime state (CVE sync, repo override, calibration)",
}


def data(f: dict[str, Any]) -> str:
    rows = []
    for name, cols in f["tables"].items():
        cell = ", ".join(f"{c}{' (PK)' if k == 'PK' else ' (FK)' if k == 'FK' else ''}" for c, _t, k in cols)
        rows.append([code(name), esc(TABLE_PURPOSE.get(name, "")), f'<span class="muted">{esc(cell)}</span>'])
    keys = [
        ["<code>create_pr:{job}</code>", "result of PR creation", "replayed on a retry or resume"],
        ["<code>notify:{job}:{event}:{channel}</code>", "notification sent", "a channel is never notified twice for the same event"],
        ["<code>audit:{job}[:{run}]</code>", "audit trail flushed", "includes <code>run_id</code> so a re-queued job is audited again"],
        ["<code>gh_delivery:{id}</code>", "webhook processed", "GitHub redeliveries ignored"],
        ["<code>jira_comment:{job}</code> · <code>jira_assign:{job}</code>", "JIRA comment / assignee set", "once per job"],
    ]
    return section("data", "Data model", f"""
<p>PostgreSQL 16. Migrations are Alembic (<code>alembic/versions/</code>): <code>0001</code> core schema (plus the append-only trigger on <code>audit_events</code>), <code>0002</code> the LangGraph checkpoint tables (their DDL is taken from the pinned library so it stays in step), <code>0003</code> <code>sync_state</code>. The checkpointer's own <code>setup()</code> runs only when <code>ENVIRONMENT=local</code>; elsewhere Alembic owns the tables.</p>
<h3>Tables <span class="muted">(generated from the ORM; the four LangGraph tables <code>checkpoints</code>, <code>checkpoint_blobs</code>, <code>checkpoint_writes</code>, <code>checkpoint_migrations</code> are excluded from autogenerate)</span></h3>
{table(["Table", "Purpose", "Columns"], rows, compact=True)}
<h3>Job statuses</h3>
<p>{" ".join(code(s) for s in f["job_statuses"])}</p>
{callout("warn", "Defined but never set", "<p><code>FIX_GENERATED</code>, <code>SANDBOX_RUNNING</code>, <code>TESTING</code> and <code>SCAN_RUNNING</code> come from the spec's lifecycle but nothing writes them. A job goes <code>QUEUED → RUNNING →</code> a final status. Use the graph trace to see progress inside a run.</p>")}
<h3>Idempotency keys</h3>
{table(["Key", "Records", "Effect"], keys, compact=True)}
<h3>Other shared state</h3>
{ul([
    "<b>sync_state keys:</b> <code>cve_sync</code> (cursor and retry ids), <code>repo_filter_override</code>, <code>confidence_calibration</code>.",
    "<b>Redis keys:</b> <code>cve-remediation:repo-lock:&lt;repo, lower-case&gt;</code>, <code>cve-remediation:sandbox-slots</code> (sorted set of leases), plus Celery's queue lists named after the four queues.",
])}
<h3>Audit event types <span class="muted">(generated)</span></h3>
<p>{" ".join(code(e) for e in f["event_types"])}</p>""")


GROUPS = [
    ("Runtime and secrets", [
        ("ENVIRONMENT", "<code>local | dev | staging | prod</code>. Prod hides the API docs; the checkpointer creates its own tables only in local."),
        ("SECRETS_BACKEND", "<code>env</code> reads the environment / <code>.env</code>; <code>aws</code> overlays values from AWS Secrets Manager."),
        ("AWS_REGION", "Region for Secrets Manager and S3."), ("AWS_SECRETS_PREFIX", "Prefix of secret names in Secrets Manager, e.g. <code>cve-remediation/GITHUB_TOKEN</code>."),
        ("CHECKPOINT_SETUP_ON_START", "Force the checkpointer to create its tables at start-up (default: only in local)."),
        ("AUTOMATION_ENABLED", "<b>Global kill-switch.</b> Off: no agent runs and no new jobs are created."),
    ]),
    ("Database and queue", [
        ("DATABASE_URL", "<code>postgresql+asyncpg://…</code>. The checkpointer's plain DSN is derived from it."), ("REDIS_URL", "Locks and the sandbox-slot semaphore."),
        ("CELERY_BROKER_URL", "Broker (Redis)."), ("CELERY_RESULT_BACKEND", "Result backend (Redis)."),
    ]),
    ("GitHub", [
        ("GITHUB_TOKEN", "Fine-grained PAT, scoped per repo. Used for reads, PRs and the host-side clone."), ("GITHUB_WEBHOOK_SECRET", "HMAC secret of the organisation webhook."),
        ("GITHUB_ORG", "Organisation whose repositories are scanned."), ("GITHUB_API_URL", "API base (set for GitHub Enterprise Server)."),
        ("GITHUB_SECONDS_BETWEEN_REQUESTS", "PyGithub pacing against secondary rate limits."), ("GITHUB_SECONDS_BETWEEN_WRITES", "Pacing between write calls (GitHub advises 1 s)."),
    ]),
    ("LLM", [
        ("LLM_API_BASE_URL", "Base URL; the client calls <code>POST {base}/chat/completions</code>."), ("LLM_API_KEY", "Sent as a bearer token."),
        ("LLM_MODEL_NAME", "Model name in the request."), ("LLM_MAX_TOKENS", "Completion limit."), ("LLM_TIMEOUT_SECONDS", "Per-request timeout."),
        ("LLM_CONTEXT_MAX_TOKENS", "Budget for the context sent (estimated at 4 characters per token)."),
    ]),
    ("CVE feeds", [
        ("NVD_API_KEY", "Raises the NVD rate limit from 5 to 50 requests per 30 s."), ("NVD_API_BASE_URL", "NVD CVE API 2.0 endpoint."),
        ("OSV_API_BASE_URL", "OSV API."), ("CVE_HTTP_TIMEOUT_SECONDS", "Timeout for NVD and OSV calls."),
        ("MIN_CVSS_THRESHOLD", "Triage cut-off (KEV CVEs ignore it)."),
    ]),
    ("Pipeline", [
        ("MAX_NEW_JOBS_PER_RUN", "Most jobs a single matcher run may create."), ("FAILED_JOB_RETRY_AFTER_HOURS", "Cool-down before a FAILED job is re-queued."),
        ("SLA_ESCALATION_AFTER_HOURS", "Age after which a Critical CVE with no PR is escalated."), ("SYFT_BIN", "Path or name of the Syft binary."),
        ("SBOM_TIMEOUT_SECONDS", "Syft time limit."), ("REPO_LOCK_TTL_SECONDS", "Per-repo lock lifetime (keep above the longest job)."),
        ("REPO_ALLOWLIST", "Comma-separated repos to include (empty = all)."), ("REPO_BLOCKLIST", "Comma-separated repos to exclude."),
        ("S3_ENDPOINT_URL", "Set for MinIO; leave empty for real AWS S3."), ("S3_ACCESS_KEY", "S3 / MinIO key (use an IAM role in AWS)."), ("S3_SECRET_KEY", "S3 / MinIO secret."),
        ("S3_BUCKET_SBOM", "Versioned bucket for SBOM documents."), ("S3_BUCKET_LOGS", "<b>Unused</b> (job logs are not written to S3 yet)."),
    ]),
    ("Fix agent and sandbox", [
        ("MAX_FIX_ATTEMPTS", "Repair-loop limit."), ("REACHABILITY_MODE", "<code>enforce</code> skips unreachable CVEs; <code>advisory</code> fixes and annotates the PR."),
        ("REQUIRE_TESTS", "Refuse to auto-fix repos without tests."), ("SUPPLY_CHAIN_VERIFY", "Require the target version to be an advisory fix version."),
        ("CONTEXT_FILE_ALLOWLIST_ENFORCED", "Only let the model edit files it was shown."), ("REDACT_SECRETS_IN_AUDIT", "Redact secrets from prompts, state, audit and PRs."),
        ("SANDBOX_NETWORK_MODE", "<code>none</code> or <code>registry-allowlist</code> (needed for dependency installs)."), ("SANDBOX_IMAGE_PYTHON", "Sandbox image tag."),
        ("SANDBOX_EGRESS_NETWORK", "Name of the internal Docker network used in allowlist mode."), ("SANDBOX_ALLOW_NON_INTERNAL_NETWORK", "Local development only: allow a normal bridge network."),
        ("SANDBOX_PROXY_URL", "Proxy exported as HTTP(S)_PROXY for install steps."), ("SANDBOX_PIP_INDEX_URL", "Internal package index for pip."),
        ("SANDBOX_TIMEOUT_SECONDS", "Per-command timeout in the sandbox."), ("SANDBOX_MEM_LIMIT", "Container memory (no swap)."), ("SANDBOX_CPU_QUOTA", "CPU quota per 100000 µs period (50000 = half a CPU)."),
        ("SANDBOX_PIDS_LIMIT", "Process limit."), ("SANDBOX_WORKSPACE_TMPFS", "Size of the workspace tmpfs."), ("SANDBOX_VENV_TMPFS", "Size of the venv tmpfs."),
        ("MAX_CONCURRENT_SANDBOXES", "Cap on live sandboxes."), ("SANDBOX_SLOTS_BACKEND", "<code>local</code> per process, <code>redis</code> shared by all workers."),
        ("SANDBOX_SLOT_LEASE_SECONDS", "How long a crashed worker's slot stays taken."),
    ]),
    ("Pull requests and notifications", [
        ("PR_BRANCH_PREFIX", "Branch prefix; also how bot PRs are recognised."), ("PR_LABELS", "Labels applied to every PR."), ("OWNER_EMAIL_DOMAIN", "Maps <code>@user</code> to <code>user@domain</code> for recipients."),
        ("ENABLED_NOTIFICATION_CHANNELS", "Comma-separated: teams, webhook, email, pagerduty."), ("TEAMS_API_ENDPOINT", "Internal Teams API URL."), ("TEAMS_API_KEY", "Bearer token for it."),
        ("WEBHOOK_URL", "Outbound webhook target."), ("WEBHOOK_SECRET", "HMAC key signing outbound webhooks."), ("SMTP_HOST", "SMTP server."), ("SMTP_PORT", "SMTP port (STARTTLS)."),
        ("SMTP_USER", "SMTP login."), ("SMTP_PASSWORD", "SMTP password."), ("EMAIL_FROM", "Sender address."), ("PAGERDUTY_ROUTING_KEY", "Events API v2 routing key."),
    ]),
    ("JIRA and Confluence", [
        ("JIRA_BASE_URL", "Atlassian site URL."), ("JIRA_PROJECT_KEY", "Project for tickets."), ("JIRA_USER", "Account (email) for basic auth."), ("JIRA_API_TOKEN", "API token; its presence turns JIRA on."),
        ("JIRA_ISSUE_TYPE", "Issue type name; must exist in the project."), ("JIRA_SEVERITIES", "Severities that get a ticket."), ("JIRA_STATUS_TRANSITIONS", "JSON map: job status → JIRA status name."),
        ("CONFLUENCE_BASE_URL", "Atlassian site URL."), ("CONFLUENCE_SPACE_KEY", "Space for pages."), ("CONFLUENCE_PARENT_PAGE_ID", "Pages are created under this page."),
        ("CONFLUENCE_USER", "Account (email) for basic auth."), ("CONFLUENCE_API_TOKEN", "API token; its presence turns Confluence on."),
    ]),
    ("Control API and observability", [
        ("API_KEY", "Control API key (required; fails closed when empty)."), ("CONTROL_API_IP_ALLOWLIST", "Comma-separated IPs/CIDRs allowed to call the API."),
        ("CONTROL_API_URL", "Public base URL used in PR descriptions and ticket links."),
        ("CLOUDWATCH_NAMESPACE", "<b>Unused</b> (observability is not built)."), ("XRAY_ENABLED", "<b>Unused</b> (observability is not built)."),
    ]),
]


def config(f: dict[str, Any]) -> str:
    by_name = {s["name"]: s for s in f["settings"]}
    described = {name for _g, items in GROUPS for name, _d in items}
    missing = set(by_name) - described
    if missing:
        raise SystemExit(f"settings without a description in scripts/handover_b.py: {sorted(missing)}")
    unknown = described - set(by_name)
    if unknown:
        raise SystemExit(f"descriptions for settings that no longer exist: {sorted(unknown)}")
    rows = []
    for group, items in GROUPS:
        for name, desc in items:
            s = by_name[name]
            default = '<span class="muted">secret</span>' if s["secret"] else '<span class="muted">unset</span>' if s["default"] == "None" else code(s["default"][:60])
            rows.append([f'<span class="muted">{esc(group)}</span>', code(name), default, desc])
    return section("config", "Configuration", f"""
<p>All configuration is typed in <code>src/core/config.py</code> (pydantic-settings). Values come from the process environment, then <code>.env</code>; with <code>SECRETS_BACKEND=aws</code> the secret fields are overlaid from AWS Secrets Manager. <code>.env.example</code> lists every variable. Nothing reads a credential anywhere except through this module.</p>
<div class="toolbar"><input type="search" id="settings-filter" data-filter-for="settings-table" placeholder="Filter {len(rows)} settings (name, default, description)" aria-label="Filter settings"><span class="muted" id="settings-table-count">{len(rows)} of {len(rows)} shown</span></div>
{table(["Group", "Setting", "Default", "Meaning"], rows, compact=True, table_id="settings-table")}
<p class="muted">Generated: {len(rows)} settings, {sum(1 for s in f["settings"] if s["secret"])} of them secrets.</p>""")
