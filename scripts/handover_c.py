"""Hand-over content, part 3: security, testing, setup, runbook, how-to, decisions, risks, backlog, repo map, glossary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.handover_lib import ROOT, callout, chip, code, esc, pre, section, table, ul


def security() -> str:
    rows = [
        ["Control API authentication", "<code>src/api/dependencies.py</code>", "API key in constant time; fails closed; optional IP/CIDR allowlist", "<code>tests/integration/test_api.py</code>"],
        ["Webhook authenticity", "<code>src/api/routers/webhooks.py</code>", "HMAC-SHA256 over the raw body, fails closed, delivery de-duplication, 5 MB cap", "GitHub's published test vector in <code>tests/contract/</code>"],
        ["Sandbox isolation", "<code>src/services/sandbox/docker_sandbox.py</code>", "Non-root, no capabilities, read-only root, no network, resource limits, no secrets inside", "<code>tests/integration/test_docker_sandbox.py</code> inspects the live container"],
        ["Prompt injection", "<code>src/agent/nodes/fix_generator.py</code>", "Delimited untrusted data, path and content validation, CI files hard-denied", "Golden case <code>prompt_injection</code>"],
        ["Secret leakage", "<code>src/core/redaction.py</code>", "Pattern redaction before prompt, state, audit, Confluence and PR", "Golden case <code>secret_redaction</code>, unit tests"],
        ["Malicious or wrong version", "<code>context_assembler.py</code>, <code>dependency_resolver.py</code>", "Target must be an advisory fix; the installed version must reach it; grype must stop reporting the CVE", "Golden cases <code>wrong_fix_blocks</code>, <code>vendored_copy</code>"],
        ["Unreviewed change", "<code>pr_creator.py</code>", "The bot only opens PRs. Review is requested from CODEOWNERS. It never merges", "—"],
        ["Duplicate side effects", "<code>src/services/idempotency.py</code>", "Keys for PRs, notifications, audit; PR dedup guard; webhook delivery ids", "<code>tests/integration/test_pause_resume.py</code>, <code>test_graph_pr_flow.py</code>"],
        ["Tamper-evident history", "migration <code>0001</code>", "A database trigger rejects UPDATE and DELETE on <code>audit_events</code>", "<code>tests/integration/test_migrations.py</code>"],
        ["Emergency stop", "<code>AUTOMATION_ENABLED</code>", "Off: no jobs are created and queued jobs are skipped", "<code>tests/integration/test_pipeline_db.py</code>"],
    ]
    return section("security", "Security model", f"""
{table(["Threat", "Where", "Control", "Proof"], rows, compact=True)}
<h3>Accepted residual risks (from the locked design)</h3>
{ul([
    "The GitHub credential is a long-lived, user-tied fine-grained PAT and commits are not signed. Rotate it on a schedule.",
    "The IP allowlist checks the TCP peer only; add mTLS or a trusted proxy in front for production.",
    "Source code and prompts are sensitive data: the audit table and any future S3 job logs must be access controlled even though secrets are redacted.",
])}""")


def testing(f: dict[str, Any]) -> str:
    c = f["test_counts"]
    suites = [
        [code("tests/unit"), str(c["unit"]), "Nothing external", "Pure logic and every graph node with fakes: routing, redaction, parsing, scoring, notifications, clients over <code>httpx.MockTransport</code>", "seconds"],
        [code("tests/integration"), str(c["integration"]), "Postgres, Redis, MinIO, Docker, Syft, internet (each test skips itself if its service is missing)", "Whole graph runs with fakes, DB stores, the matcher, the Celery task bridge, the API, a real Celery worker process, real Docker sandboxes, real Syft and S3", "about 70 s"],
        [code("tests/contract"), str(c["contract"]), "Nothing (live checks are opt-in)", "Every payload we send validates against the provider's JSON Schema; PyGithub talks real HTTP to a fake GitHub server", "about 10 s"],
        [code("tests/eval"), str(c["eval"]), "Docker, the sandbox image, PyPI", "The golden-CVE evaluation. Excluded from the default run", "about 4 min"],
    ]
    cases = []
    ev = f.get("eval")
    if ev:
        for case in ev["cases"]:
            cases.append([code(case["name"]), chip("done", "PASS") if case["passed"] else chip("todo", "FAIL"), code(str(case["terminal_status"])), str(case["fix_attempts"]), str(case["diff_lines"]), f'{case["duration_s"]:.0f} s'])
    gate = ev["gate"] if ev else None
    gate_line = ""
    if gate:
        m = gate["metrics"]
        gate_line = f'<p>Last recorded gate: {chip("done", "PASS") if gate["passed"] else chip("todo", "FAIL")} · pass rate {m["pass_rate"]} · fix success rate {m["fix_success_rate"]} · false fixes {m["false_fix_count"]} · safety failures {m["safety_failures"]} (mode: {esc(ev["mode"])}).</p>'
    return section("testing", "Testing and quality gates", f"""
<h3>Suites <span class="muted">(counts generated)</span></h3>
{table(["Suite", "Tests", "Needs", "What it covers", "Time"], suites, compact=True, num_cols={1})}
{pre('pytest -q                          # default: unit + integration + contract\npytest tests/unit -q                # fast loop, no services\npytest -m "not docker" -q           # skip the real-Docker tests\nCONTRACT_LIVE=1 pytest tests/contract/test_live.py -v   # real NVD / OSV / PyPI (+ GitHub, Atlassian, LLM with credentials)\npython -m tests.eval.run            # golden evaluation, replay mode\npython -m tests.eval.run --mode live   # same cases, your real LLM')}
<p>Markers: <code>db</code>, <code>docker</code>, <code>redis</code>, <code>celery</code>, <code>s3</code>, <code>syft</code>, <code>contract_live</code>, <code>eval</code>. The default run deselects <code>eval</code> and ignores <code>tests/eval/cases/</code> (the golden repositories contain test files that are fixtures, not tests of this project).</p>
<h3>Helpers you will use constantly</h3>
{ul([
    "<code>tests/fakes.py</code>: <code>FakeSandbox</code> / <code>FakeSandboxManager</code> (scriptable pytest output, installs, grype), <code>FakePRService</code>, in-memory idempotency, audit and notification stores, <code>RecordingHandler</code>.",
    "<code>tests/conftest.py</code>: <code>make_state</code> (a valid <code>AgentState</code>), <code>agent_deps</code> (installs all fakes through <code>override_deps</code>), <code>migrated_db</code> (a scratch Postgres database with every migration applied, dropped afterwards).",
    "<code>tests/llm_helpers.py</code>: <code>chat()</code>, <code>good()</code> and <code>Recorder</code> to fake the OpenAI-compatible LLM.",
    "Dependencies reach nodes through <code>src/agent/deps.py</code> (<code>override_deps(...)</code>), because LangGraph fixes the node signature to <code>(state) → dict</code>.",
])}
{callout("warn", "Three traps", "<p><b>Clocks:</b> job timestamps come from the database clock, so tests that pass a fake <code>now</code> to the matcher must keep it near the real time. "
 "<b>Retries sleep for real</b> unless a test patches <code>asyncio.sleep</code> in <code>src.utils.retry</code>; an unpatched test that retries takes seconds. "
 "<b>The real-internet tests can flake:</b> the Docker tests that install from PyPI skip or fail when the network is unavailable (one did during the final run and passed on rerun). Rerun before suspecting the code.</p>")}
<h3>Golden-CVE evaluation <span class="muted">tests/eval/</span></h3>
<p>Each case in <code>cases/&lt;name&gt;/</code> is a tiny repository, an advisory and the outcome a correct system must produce. The harness runs the <b>real graph</b> (real Docker sandbox, PyPI install, pytest and Grype); only GitHub and the database are in memory. The model is either <b>replay</b> (recorded answers, deterministic, tests everything around the model) or <b>live</b> (your endpoint, tests the model). Checks are <i>quality</i> (outcome, attempts, confidence, diff size, scanner) or <i>safety</i> (no PR where none is allowed, only expected files change, forbidden files untouched, secrets absent from prompts, PR and audit, no container left behind). Any safety failure fails the gate whatever the pass rate; thresholds are in <code>gate.yaml</code> (replay 100%, live 80%).</p>
{gate_line}
{table(["Case", "Result", "Status", "Attempts", "Diff lines", "Time"], cases, compact=True, num_cols={3, 4}) if cases else ""}
<h3>Contract tests <span class="muted">tests/contract/</span></h3>
{ul([
    "<code>schemas.py</code> holds JSON Schemas for what we send: chat-completions, Teams, PagerDuty Events v2, JIRA v3 (including Atlassian Document Format), Confluence v1, and GitHub REST bodies. The Teams schema is <b>our assumption</b>; change it first if the real API differs.",
    "<code>fake_github.py</code> is a small HTTP server that speaks the GitHub endpoints the code uses. PyGithub runs for real against it, so tests see the actual wire format (tree contents, executable mode, ref names, team reviewer slug, label bodies).",
    "<code>test_schema_sanity.py</code> proves the schemas reject known-bad payloads. <code>test_live.py</code> (opt in with <code>CONTRACT_LIVE=1</code>) is read-only against NVD, OSV, PyPI and npm, and, with credentials, GitHub, JIRA (it checks the priority names and issue type really exist), Confluence and the LLM.",
])}""")


def setup() -> str:
    return section("setup", "Local setup", f"""
<p>Requirements: macOS or Linux, Docker with Compose, <a href="https://docs.astral.sh/uv/">uv</a> (used only to fetch Python 3.12), git.</p>
<ol>
<li><b>Python environment</b>{pre("uv venv --python 3.12 .venv && source .venv/bin/activate\nuv pip install -r requirements-dev.txt")}</li>
<li><b>Services</b> (PostgreSQL 16, Redis, MinIO){pre("docker compose up -d postgres redis minio\npython -m scripts.init_local_storage    # creates the two versioned buckets")}</li>
<li><b>Environment file.</b> Copy <code>.env.example</code> to <code>.env</code> (git-ignored). For tests the defaults work, apart from the MinIO keys and Syft: {pre("S3_ACCESS_KEY=minioadmin\nS3_SECRET_KEY=minioadmin\nSYFT_BIN=/path/to/syft")}Download a checksum-verified Syft into <code>.tools/</code> or install it on your PATH.</li>
<li><b>Database schema</b>{pre("alembic upgrade head")}</li>
<li><b>Sandbox image</b> (4 GB; downloads Grype and its vulnerability database){pre("docker build -f docker/sandbox/python.Dockerfile -t cve-sandbox-python docker/sandbox")}</li>
<li><b>Check everything</b>{pre("pytest -q")}</li>
</ol>
{callout("", "Smoke tests that touch the real internet", "<p><code>python -m scripts.smoke_aggregate CVE-2024-21626</code> fetches one CVE from NVD and OSV and stores it. <code>CONTRACT_LIVE=1 pytest tests/contract/test_live.py</code> does the same for a wider set of services.</p>")}
<h3>If something fails</h3>
{table(["Symptom", "Likely cause"], [
    ["Docker tests skip", "Docker Desktop is not running, or the sandbox image is not built."],
    ["<code>docker compose up</code> cannot pull MinIO", "Official MinIO images are no longer published; the compose file uses <code>chainguard/minio</code>."],
    ["Tests that need Postgres or Redis skip", "The containers are not up; they probe the default ports."],
    ["Sandbox install says SANDBOX_NETWORK_MODE=none", "Dependency installs need <code>registry-allowlist</code> and an egress network. For local runs set <code>SANDBOX_NETWORK_MODE=registry-allowlist SANDBOX_EGRESS_NETWORK=bridge SANDBOX_ALLOW_NON_INTERNAL_NETWORK=true</code>."],
    ["A fix is blocked because Grype misses a new CVE", "The baked vulnerability database in the sandbox image is old. Rebuild the image."],
], compact=True)}""")


def runbook() -> str:
    return section("runbook", "Runbook", f"""
<p>Commands assume the Control API at <code>$API</code> with <code>$API_KEY</code>, and PostgreSQL/Redis reachable with <code>psql</code> / <code>redis-cli</code>.</p>
<h3>Stop everything safely</h3>
<p>Set <code>AUTOMATION_ENABLED=false</code> and restart the API and workers (settings are read at start-up). No new jobs are created and queued jobs are skipped but stay <code>QUEUED</code>. <b>A run already in progress is not interrupted</b> (the switch is checked when a run starts); pause it through the API if it must stop. Turn it back on and the matcher re-queues what was lost (a queued job older than 6 hours is re-sent).</p>
<h3>Follow one job</h3>
{pre('curl -s -H "X-API-Key: $API_KEY" $API/api/v1/jobs/$JOB_ID                 # status, audit events, links\ncurl -s -H "X-API-Key: $API_KEY" $API/api/v1/jobs/$JOB_ID/graph-trace     # which node ran, what runs next\n# logs are JSON with job_id on every line:\ngrep \'"job_id": "\'$JOB_ID\'"\' worker.log')}
<h3>A job is stuck in RUNNING</h3>
<p>Normal: the task is still working (three attempts can take half an hour). Abnormal: no worker is processing it. The task marks a job FAILED after its retries, but a hard-killed worker can leave it RUNNING; there is no watchdog yet.</p>
{pre("select job_id, repo_name, cve_id, updated_at from remediation_jobs where status = 'RUNNING' and updated_at < now() - interval '4 hours';\n-- confirm nothing holds its repo:   redis-cli get cve-remediation:repo-lock:org/repo\nupdate remediation_jobs set status = 'FAILED' where job_id = '...';   -- the matcher retries it after FAILED_JOB_RETRY_AFTER_HOURS")}
<h3>Re-run a BLOCKED or NOT_REACHABLE job</h3>
<p>Those statuses are final on purpose (a human or a rule decided). To retry one deliberately, make it look like an old failure so the next matcher run re-queues it:</p>
{pre("update remediation_jobs set status = 'FAILED', updated_at = now() - interval '25 hours' where job_id = '...';")}
<h3>Locks, slots, containers</h3>
{pre("redis-cli del cve-remediation:repo-lock:org/repo               # repo lock left by a killed worker (it expires after 3 h anyway)\nredis-cli zrange cve-remediation:sandbox-slots 0 -1 withscores   # live sandbox leases\nredis-cli del cve-remediation:sandbox-slots                       # only if you are sure no sandbox is running\ndocker ps -a --filter label=cve-remediation.sandbox=1             # sandboxes (label cve-remediation.job_id names the job)\ndocker rm -f $(docker ps -aq --filter label=cve-remediation.sandbox=1)\nredis-cli llen remediation                                        # queue depth (also: scanning, notifications, audit)")}
<h3>Sandbox image</h3>
<p>Rebuild at least daily in production (CI): the Grype database is part of the image and is not updated at run time. A new Grype release can also change the database schema, which is why <code>GRYPE_VERSION</code> is pinned in the Dockerfile and was bumped from 0.86.1 to 0.120.1.</p>
{pre("docker build --no-cache -f docker/sandbox/python.Dockerfile -t cve-sandbox-python docker/sandbox")}
<h3>Useful questions for SQL</h3>
{pre("-- why did a job end the way it did?\nselect ts, event_type, left(payload::text, 200) from audit_events where job_id = '...' order by ts, id;\n-- which notifications failed?\nselect channel, error, attempted_at from notification_log where status = 'failed' order by attempted_at desc limit 20;\n-- how are reviewers treating the bot?\nselect outcome, count(*), avg(predicted_confidence) from pr_outcomes group by outcome;\n-- jobs by status\nselect status, count(*) from remediation_jobs group by status order by 2 desc;")}
<h3>Other routine tasks</h3>
{ul([
    "<b>Exempt a repo:</b> add the <code>cve-exempt</code> topic on GitHub, or <code>PATCH /api/v1/config/repos</code> with a blocklist.",
    "<b>Rotate a secret:</b> change it in the environment or Secrets Manager, then restart the processes that use it (configuration is read once at start).",
    "<b>Run a scan now:</b> <code>POST /api/v1/scan/trigger</code> (optionally <code>{\"repo_names\": [\"org/repo\"]}</code>) or <code>POST /api/v1/scan/cve/CVE-…</code>.",
    "<b>Change the schema:</b> <code>alembic revision --autogenerate -m \"…\"</code>, review the file, <code>alembic upgrade head</code>. The LangGraph tables are excluded from autogenerate on purpose.",
])}""")


def howto() -> str:
    guides = [
        ("Add a graph node", [
            "Create <code>src/agent/nodes/&lt;name&gt;.py</code> with <code>@agent_node(\"name\") async def name(state) -&gt; dict</code>. Return only changed fields, and add your audit event with <code>with_event</code> / <code>make_event</code>. Repairable failures return <code>record_failure(state, reason)</code>; unexpected ones raise (the decorator turns them into <code>FAILED</code>).",
            "Export it in <code>src/agent/nodes/__init__.py</code>, add a pure <code>route_after_&lt;name&gt;</code> to <code>routing.py</code> (with a test in <code>tests/unit/agent/test_routing.py</code>), and register node and edges in <code>graph.py</code>.",
            "Reach external systems only through <code>src/agent/deps.py</code> so tests can substitute them. Add the state fields to <code>AgentState</code>.",
            "Extend a scenario in <code>tests/integration/test_graph_repair_loop.py</code> or <code>test_graph_pr_flow.py</code> and, if behaviour changes, a golden case.",
        ]),
        ("Add an ecosystem (for example npm)", [
            "Sandbox: a Dockerfile under <code>docker/sandbox/</code>, an entry in <code>_IMAGES</code> in <code>docker_sandbox.py</code> and a setting for the image.",
            "Replace the pip-only pieces: <code>_pip.py</code> (install command), <code>test_runner.py</code> (command and output parser; the node is hard-wired to pytest today), <code>dependency_resolver.py</code> (version check), <code>security_scanner.py</code> (scan targets), <code>sandbox_executor.py</code> (the ecosystem guard).",
            "Analysis: a reachability analyser in <code>reachability.py</code>, import names in <code>src/utils/packages.py</code>, the search language map in <code>context_assembler.py</code>.",
            "Matching already works (SBOM purl mapping, name canonicalisation, range evaluation). Add golden cases for the new ecosystem before trusting it.",
        ]),
        ("Add a notification channel", [
            "Subclass <code>NotificationHandler</code> in <code>src/services/notifications/&lt;channel&gt;.py</code> (<code>name</code>, <code>supports()</code>, <code>send()</code> that raises on failure).",
            "Register it in <code>HANDLERS</code> in <code>dispatcher.py</code>, add its settings (see below), and list it in <code>ENABLED_NOTIFICATION_CHANNELS</code>.",
            "Add a payload schema to <code>tests/contract/schemas.py</code> and a test that validates what the handler sends. Idempotency and logging come from the dispatcher.",
        ]),
        ("Add a golden case", [
            "Create <code>tests/eval/cases/&lt;name&gt;/</code> with <code>repo/</code> (the files), <code>case.yaml</code> (advisory, job and <code>expect</code>), and <code>llm_responses.json</code> (the model answers to replay, in order; the last repeats).",
            "Use <code>replay_only: true</code> for scripted bad behaviour. Pick packages that install on Python 3.12 (an old urllib3 does not).",
            "Run <code>python -m tests.eval.run --cases &lt;name&gt;</code>. <code>tests/unit/test_eval_harness.py</code> checks that every recording is valid model output.",
        ]),
        ("Add a setting", [
            "Add the typed field to <code>Settings</code> in <code>src/core/config.py</code>; secrets are <code>SecretStr</code> and also go in <code>SECRET_NAMES</code> in <code>secrets.py</code>.",
            "Add it to <code>.env.example</code> and give it a description in <code>scripts/handover_b.py</code> (the document build fails if one is missing).",
        ]),
        ("Add an API route", [
            "Put it in a router under <code>src/api/routers/</code> with <code>dependencies=Authed</code> (an unauthenticated route needs a reason), register the router in <code>main.py</code>, and take collaborators (such as the task queue) through <code>Depends</code> so tests can override them.",
            "Test it in <code>tests/integration/test_api.py</code>, including the 401 case; the file already loops over every protected route.",
        ]),
        ("Replace PyGithub with the GitHub MCP server", [
            "Implement <code>GitHubContentSource</code> (<code>src/services/github/client.py</code>) and <code>PullRequestService</code> (<code>pr_creator.py</code>) on top of MCP, using fixed call sequences rather than a model-driven tool loop (the locked design).",
            "Swap them in <code>get_content_source()</code> and <code>get_pr_service()</code> in <code>deps.py</code>. Keep <code>tests/contract/test_github_wire.py</code> as the specification of what must be produced; adapt the fake server to the MCP transport.",
        ]),
        ("Point the system at a different LLM", [
            "Everything model-specific is in <code>src/agent/nodes/fix_generator.py</code> (<code>LLMClient</code> and the prompts). Change the request or response handling there, update <code>LLM_REQUEST</code>/<code>LLM_RESPONSE</code> in <code>tests/contract/schemas.py</code>, then run the live contract and live evaluation.",
        ]),
    ]
    body = "".join(f"<details><summary>{esc(title)}</summary><ol>{''.join(f'<li>{s}</li>' for s in steps)}</ol></details>" for title, steps in guides)
    return section("howto", "How to change things", f"<p>Step-by-step recipes for the changes you are most likely to make.</p>{body}")


def decisions() -> str:
    rows = [
        ["GitHub access", "PyGithub for everything; the MCP transport is not built", chip("partial", "Deviation"), "Interfaces (<code>GitHubContentSource</code>, <code>PullRequestService</code>) are in place; the spec fixes MCP for context assembly and PR creation. No MCP server or transport was specified."],
        ["KEV and the CVSS threshold", "KEV CVEs are never dropped, even when below the threshold or unscored", chip("partial", "Deviation"), "Spec says drop below <code>MIN_CVSS_THRESHOLD</code>. Known-exploited vulnerabilities matter regardless of score. Change in <code>triage()</code>."],
        ["Graph edges", "Added error short-circuits (<code>route_after_context</code>, <code>route_after_fix</code>), made baseline failure keep its own status, added <code>route_after_sandbox/patch/pr</code>, and <code>write_audit</code> is not routed to <code>handle_error</code>", chip("info", "Fix"), "The spec's edges conflicted with its own text (for example an unconditional and a conditional edge from <code>run_pre_tests</code>)."],
        ["Where the repo is cloned", "On the host, copied into the container", chip("info", "Choice"), "Lets the sandbox run with no network and no token."],
        ["Sandbox egress", "An internal Docker network fronted by an allowlisting proxy (<code>registry-allowlist</code>)", chip("info", "Choice"), "Docker cannot attach a network to a container started with <code>none</code>, so connect/disconnect around installs was not possible."],
        ["Sandbox image", "<code>python:3.12-slim</code> plus git and Grype with the database baked in", chip("info", "Choice"), "Spec names the base image only. Grype 0.120.1 (the pinned 0.86.1 could only read an obsolete database schema)."],
        ["Files into the sandbox", "tar stream through <code>exec</code>, not heredocs or <code>put_archive</code>", chip("info", "Choice"), "No shell quoting; <code>put_archive</code> is refused on read-only root filesystems."],
        ["Repos without tests", "Not auto-fixed (<code>NO_TESTS</code>, <code>REQUIRE_TESTS=true</code>)", chip("info", "Policy"), "A PR with no validation would be a guess. Set it to false to allow."],
        ["Confidence tiers", "HIGH ≥ 85, MEDIUM ≥ 70, then recalibrated weekly", chip("info", "Assumption"), "Spec has tier names without numbers."],
        ["Existing PR for the same CVE", "Skip (<code>PR_EXISTS</code>) rather than update", chip("info", "Choice"), "Spec says skip/update. Updating needs a push to an existing branch."],
        ["\"Merged with edits\"", "More than one commit on the PR", chip("info", "Heuristic"), "The original commit SHA is not stored."],
        ["Tracking before the PR", "JIRA ticket and Confluence page are created before the agent runs", chip("info", "Choice"), "The PR template needs both links, so they must exist first. Tickets exist even for jobs that end BLOCKED."],
        ["LLM API", "OpenAI-compatible <code>/chat/completions</code> with JSON mode", chip("info", "Assumption"), "Spec marks this as adaptable. Single adaptation point: <code>fix_generator.py</code>."],
        ["Teams API", "Bearer token, payload from the spec", chip("info", "Assumption"), "Adapt in <code>src/services/notifications/teams.py</code> and the contract schema."],
        ["Local object storage", "<code>chainguard/minio</code>", chip("info", "Environment"), "Official MinIO images are no longer published."],
        ["Pause", "Cooperative, between graph steps", chip("info", "Limit"), "A long node delays it. True interruption needs node-level checkpoints."],
        ["Job statuses", "Only <code>QUEUED</code>, <code>RUNNING</code> and final states are set", chip("info", "Limit"), "Intermediate states from the spec exist in the enum but are unused; the graph trace covers progress."],
    ]
    return section("decisions", "Decisions, deviations and assumptions", f"""
<p>Where this implementation departs from the specification or fills a gap. The spec's <i>Locked Design Decisions</i> section wins over the rest of the spec; items here are the places where I had to interpret.</p>
{table(["Topic", "What was done", "Kind", "Why, and where to change it"], rows, compact=True)}""")


def risks() -> str:
    rows = [
        [chip("p0", "High"), "Sandboxes need a Docker daemon", "The sandbox uses the Docker SDK. On EKS a worker pod has no Docker daemon. Options: Docker-in-Docker sidecar (privileged, weakens isolation), a dedicated node pool with the socket (also weak), or a Kubernetes-native sandbox (Jobs with gVisor/Kata). <b>Decide this before building the infrastructure.</b>"],
        [chip("p0", "High"), "Installs need egress that does not exist yet", "With <code>SANDBOX_NETWORK_MODE=none</code> no dependency can be installed, so nothing can be validated. The internal network plus allowlisting proxy is infrastructure that was never provisioned or tested here."],
        [chip("p0", "High"), "Never run against real systems", "LLM, Teams, JIRA, Confluence, AWS Secrets Manager and your GitHub organisation have only been faked. Expect schema, auth and naming differences. Run the live contract tests first."],
        [chip("p0", "High"), "LangGraph will block unregistered checkpoint types", "Every run logs <i>\"Deserializing unregistered type src.agent.state.FileChange … will be blocked in a future version\"</i>. When that becomes default, resuming any job with a saved <code>FileChange</code> or <code>TestResult</code> fails. Register them via <code>allowed_msgpack_modules</code> (or <code>LANGGRAPH_STRICT_MSGPACK</code> settings)."],
        [chip("p0", "High"), "Public repository with no CI or protection", "The code is public at <code>github.com/priyanshu2510/SACVE</code> (branch <code>main</code>, one commit) with no CI, branch protection, license or dependency/secret scanning configured. <code>.gitignore</code> excludes <code>.env</code>, <code>.venv/</code>, <code>.tools/</code> and <code>eval-report.json</code>; check that nothing else sensitive is ever added."],
        [chip("p1", "Medium"), "Only Python 3.12 repositories validate", "The sandbox runs Python 3.12. A repo pinned to an older stack (for example urllib3 1.26.4) fails its baseline and is reported BASELINE_FAILING. The sandbox should pick the repo's Python version."],
        [chip("p1", "Medium"), "Unsupported pip manifests", "The SBOM accepts <code>Pipfile</code>, <code>poetry.lock</code> and similar files, but the installer supports only <code>requirements*.txt</code> and <code>pyproject.toml</code>/<code>setup.py</code>/<code>setup.cfg</code>; the rest fail with \"unsupported pip manifest\". A lockfile-only change by section replacement is also unlikely to be correct."],
        [chip("p1", "Medium"), "Stale vulnerability database", "Grype's database is baked into the image. If the image is not rebuilt, new CVEs are not detected and a fix can be wrongly declared complete."],
        [chip("p1", "Medium"), "GitHub code search limits", "Search is limited to about 10 requests a minute and its index can lag. The assembler tolerates failures and the reachability check refuses to conclude \"unreachable\" from incomplete results, but a burst of jobs will be slow."],
        [chip("p1", "Medium"), "A hard-killed worker can leave a job RUNNING", "There is no watchdog; see the Runbook. The lock expires after 3 h and the slot lease after 6 h."],
        [chip("p1", "Medium"), "Context overflow", "If the CVE facts plus the manifest exceed <code>LLM_CONTEXT_MAX_TOKENS</code> (a very large manifest), the job fails with \"context too large\". Token counts are estimated at 4 characters each."],
        [chip("p2", "Low"), "Unused settings", "<code>S3_BUCKET_LOGS</code>, <code>CLOUDWATCH_NAMESPACE</code> and <code>XRAY_ENABLED</code> are defined but nothing uses them."],
        [chip("p2", "Low"), "Image size", "The sandbox image is about 4.2 GB (mostly the vulnerability database). Pre-pull it on worker nodes."],
        [chip("p2", "Low"), "Webhook behind an IP allowlist", "The allowlist also applies to the GitHub webhook. List GitHub's hook ranges or terminate at a proxy."],
    ]
    return section("risks", "Known issues and risks", f"""
<p>Ordered by how likely they are to hurt you. High items should be settled before the first production run.</p>
{table(["Severity", "Issue", "Detail and mitigation"], rows, compact=True)}
<h3>Things that already cost time (so they do not cost you time)</h3>
{ul([
    "OSV's CVE-id record has only git ranges; the package data is on its GHSA/GO aliases (fixed in <code>CVEAggregator._fetch_osv</code>).",
    "Docker refuses <code>put_archive</code> on read-only containers, and cannot attach a network to a container started with <code>--network none</code>.",
    "Grype 0.86.1 could only read a database schema that is no longer updated; keep Grype current.",
    "The Redis <code>visibility_timeout</code> must exceed the longest task or Redis redelivers it while it still runs.",
    "asyncpg connections and httpx clients cannot cross event loops; Celery tasks therefore dispose them after every task (<code>run_async</code>).",
    "PyGithub's call pacing makes a PR creation take about ten seconds, and a GitHub ref is read at <code>/git/ref/…</code> but deleted at <code>/git/refs/…</code>.",
    "A calibration based on cumulative rates would let strong PRs hide a weak band; each tier is judged on its own band.",
])}""")


def backlog() -> str:
    items = [
        ("p0", "Protect the public repository", "Branch protection on <code>main</code>, a license (a public repo without one is all rights reserved), CODEOWNERS, Dependabot and GitHub secret scanning. Decide whether this hand-over document, which lists known weaknesses, should stay in a public repo.", "S", "GitHub settings"),
        ("p0", "Decide and build the production sandbox runtime", "Docker-in-Docker, dedicated Docker hosts, or Kubernetes Jobs with gVisor/Kata. Provision the internal egress network and the registry-allowlist proxy; set <code>SANDBOX_NETWORK_MODE=registry-allowlist</code>.", "L", "docker_sandbox.py"),
        ("p0", "Verify every integration with real credentials", "Run <code>CONTRACT_LIVE=1</code> with GitHub, JIRA, Confluence and LLM configured. Fix the Teams payload, JIRA priority/issue-type/status names, LLM response handling as needed.", "M", "tests/contract/"),
        ("p0", "Run the live evaluation", "<code>python -m tests.eval.run --mode live</code> against the real model; tune prompts until the gate (80%) passes. Add cases from real repos.", "M", "tests/eval/"),
        ("p0", "Register LangGraph checkpoint types", "Allow <code>FileChange</code> and <code>TestResult</code> for msgpack deserialisation and add a test that resumes a run.", "S", "agent/runner.py"),
        ("p0", "CI pipeline", "GitHub Actions: lint, unit + integration with service containers, contract tests, replay evaluation as the release gate, build and scan images, daily sandbox-image rebuild.", "M", ".github/workflows/"),
        ("p0", "Infrastructure as code", "Terraform for S3 (versioned), RDS PostgreSQL 16 (backups), ElastiCache, EKS, Secrets Manager, IAM (least privilege); Helm chart; application Dockerfile(s); dev/staging/prod.", "L", "infra/"),
        ("p0", "Observability", "CloudWatch metrics (EMF) for fix success, PR merge rate, per-node latency, LLM tokens and cost, sandbox count, queue depth; X-Ray across Celery → LangGraph → external calls; alarms; SLOs. Use the existing <code>job_id</code> as correlation id. Wire up the unused settings.", "M", "new module"),
        ("p0", "Test Secrets Manager for real", "Only a fake client has exercised <code>AwsSecretsManagerProvider</code>. Test against AWS and define rotation.", "S", "core/secrets.py"),
        ("p1", "Per-repo Python version", "Choose the sandbox Python from <code>.python-version</code>, <code>pyproject</code> or <code>runtime.txt</code>; ship several images.", "M", "docker_sandbox.py"),
        ("p1", "GitHub MCP transport", "Locked design: MCP for context assembly and PR creation with fixed call sequences. See the how-to.", "M", "services/github/"),
        ("p1", "Remaining ecosystems", "npm, Go, Maven, NuGet, Gem: sandbox image, installer, test runner, scanner, reachability. Start with npm. Add golden cases.", "L each", "agent/nodes/"),
        ("p1", "Job watchdog", "A periodic task that fails jobs stuck in RUNNING with no live lock, and frees their sandboxes.", "S", "pipeline.py"),
        ("p1", "S3 job logs", "Write test output, scanner output and diffs to <code>S3_BUCKET_LOGS</code>, classified as sensitive.", "S", "audit_writer.py"),
        ("p1", "Handle Pipfile and poetry projects", "Support or cleanly skip, rather than failing with \"unsupported pip manifest\".", "M", "agent/nodes/_pip.py"),
        ("p1", "GitHub Advisory Database client", "Third CVE source from the spec (currently covered by NVD, OSV and the advisory webhook).", "M", "cve_aggregator/"),
        ("p1", "Update an existing PR", "Spec says skip or update; only skip exists.", "M", "pr_creator.py"),
        ("p1", "Code-search caching", "Cache results per repo to stay within GitHub's search limit during bursts.", "S", "context_assembler.py"),
        ("p1", "API hardening", "Per-caller API keys with identities in the audit event, rate limiting, mTLS in front.", "M", "api/"),
        ("p2", "Static quality gates", "mypy, ruff and a coverage floor (optional in the spec).", "S", "CI"),
        ("p2", "Store the PR commit SHA", "Replace the \"more than one commit\" heuristic for merged-with-edits.", "S", "pr_outcomes.py"),
        ("p2", "Node-level pause", "Interrupt long nodes (test runs) rather than waiting for a step boundary.", "M", "runner.py"),
        ("p2", "Real tokenizer for the context budget", "Replace the 4-characters-per-token estimate.", "S", "context_assembler.py"),
        ("p2", "Set or remove the unused job statuses", "<code>FIX_GENERATED</code>, <code>SANDBOX_RUNNING</code>, <code>TESTING</code>, <code>SCAN_RUNNING</code>.", "S", "models/job.py"),
        ("p2", "A reviewer-facing dashboard", "Not in the spec; the API and Confluence cover it today.", "L", "—"),
    ]
    rows = [[chip(p), f"<b>{esc(t)}</b><br>{d}", f'<span class="size">{esc(s)}</span>', f"<span class='muted'>{where}</span>"] for p, t, d, s, where in items]
    n0 = sum(1 for i in items if i[0] == "p0")
    return section("left", "What is left", f"""
<p><b>P0</b> = before the first production run ({n0} items). <b>P1</b> = needed for the specification's full scope or for safe operation at scale. <b>P2</b> = improvements. Sizes are rough: S about a day, M a few days, L a week or more.</p>
{table(["Priority", "Item", "Size", "Where"], rows, compact=True)}
{callout("ok", "Suggested order", "<p>Repository protection and CI first (so everything after is protected by the gate), then the real-credential verification and live evaluation (they decide how much of the rest changes), then the sandbox-runtime decision, then infrastructure and observability in parallel with the MCP adapter and npm.</p>")}""")


TREE = [
    ("src/core/", "config, secrets, logging, database engine, secret redaction"),
    ("src/models/", "SQLAlchemy models: CVE, job, audit, SBOM, notification, sync state"),
    ("src/schemas/", "Pydantic models: CVE records, API payloads"),
    ("src/utils/", "retry with jitter, rate limiter, version compare, package-name helpers, Redis locks and semaphore"),
    ("src/agent/", "LangGraph: state, graph, routing, runner (resume and pause), dependency holder"),
    ("src/agent/nodes/", "one module per node, plus <code>_common.py</code> and <code>_pip.py</code>"),
    ("src/services/cve_aggregator/", "NVD and OSV clients, normaliser, store"),
    ("src/services/triage/", "prioritiser"),
    ("src/services/sbom/", "Syft runner, CycloneDX parser, S3 archive"),
    ("src/services/matcher/", "version-range matcher, job policy, repo filter"),
    ("src/services/github/", "content source, PR service, CODEOWNERS, PR description, repo sync"),
    ("src/services/sandbox/", "Docker sandbox, host-side clone, slot limiters"),
    ("src/services/notifications/", "channels, dispatcher, log store"),
    ("src/services/confluence/ · jira/", "Atlassian publishers"),
    ("src/services/", "pipeline.py (steps behind Celery tasks), tracking.py, calibration.py, pr_outcomes.py, audit/, atlassian.py, idempotency.py, task_queue.py"),
    ("src/workers/", "Celery app, runtime bridge, tasks (scan, remediation, notification, audit)"),
    ("src/api/", "FastAPI app, dependencies, routers (scan, jobs, cves, config, webhooks)"),
    ("alembic/", "migrations 0001–0003"),
    ("docker/sandbox/", "the sandbox image"),
    ("config/", "<code>repos.yaml</code> allow/block lists"),
    ("scripts/", "smoke test, bucket init, and the generator of this document"),
    ("tests/unit · integration · contract · eval", "see Testing"),
    ("docker-compose.yml", "PostgreSQL, Redis, MinIO for local development (no application containers yet)"),
]


def repo_map() -> str:
    missing = [p for p, _ in TREE if not any((ROOT / part.strip().rstrip("/")).exists() for part in p.replace("·", " ").split() if "/" in part or "." in part)]
    if missing:
        raise SystemExit(f"repo map lists paths that do not exist: {missing}")
    rows = "".join(f'<div><span class="d">{esc(p)}</span> <span class="c">{d}</span></div>' for p, d in TREE)
    return section("map", "Repository map", f'<div class="tree">{rows}</div>')


def glossary() -> str:
    terms = [
        ("ADF", "Atlassian Document Format: the JSON document structure JIRA v3 requires for descriptions and comments."),
        ("Checkpoint", "LangGraph's saved state after each graph step, keyed by <code>thread_id</code> (= job id)."),
        ("CycloneDX", "The SBOM JSON format Syft produces."),
        ("Golden case", "A small repository plus advisory and expected outcome used by the evaluation harness."),
        ("Grype / Syft", "Anchore tools: Grype scans for known vulnerabilities, Syft lists a project's packages (the SBOM)."),
        ("KEV", "CISA's Known Exploited Vulnerabilities catalogue; exploited in the wild."),
        ("MCP", "Model Context Protocol; the GitHub MCP server is the locked design's transport for GitHub access."),
        ("Reachability", "Whether the repository's code actually uses the vulnerable package."),
        ("Repair loop", "Sending a failed attempt's reason back to the LLM for another try, up to <code>MAX_FIX_ATTEMPTS</code>."),
        ("Replay / live", "Evaluation modes: recorded model answers, or the configured LLM."),
        ("run_id", "Identifies one enqueue of a job; a resume keeps it, a re-queue gets a new one."),
        ("Safe version", "The smallest known fix version that clears every advisory range containing the installed version."),
        ("SBOM", "Software bill of materials: the dependency list of a repository."),
        ("Supply-chain check", "Refusing a target version that is not one of the advisory's published fix versions."),
    ]
    return section("glossary", "Glossary", table(["Term", "Meaning"], [[f"<b>{esc(t)}</b>", d] for t, d in terms], compact=True))
