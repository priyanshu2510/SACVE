"""Hand-over content, part 1: overview, status, architecture, the fix agent."""

from __future__ import annotations

from typing import Any

from scripts import handover_diagrams as DG
from scripts.handover_lib import callout, chip, code, esc, section, table, ul


def hero(f: dict[str, Any], today: str, suite: str) -> str:
    total_tests = sum(v for k, v in f["test_counts"].items() if k != "eval")
    stats = [
        (f"{f['loc_src']:,}", "lines of application code"), (f"{f['loc_tests']:,}", "lines of tests"),
        (f"{total_tests}", "tests in the default run"), (str(len(f["routes"])), "HTTP routes"),
        (str(len([t for t in f["tasks"] if t["name"] != "ops.ping"])), "Celery tasks"), (str(len(f["tables"])), "database tables"),
        (str(len(f["settings"])), "settings"), ("11", "golden CVE cases"),
    ]
    tiles = "".join(f'<div class="stat"><b>{esc(n)}</b><span>{esc(label)}</span></div>' for n, label in stats)
    suite_line = f"<p class=\"muted\">Last full run: {esc(suite)}.</p>" if suite else ""
    return f"""<header class="hero" id="top">
<div class="kicker">Hand-over document · generated {esc(today)} from the live code</div>
<h1>CVE Auto-Remediation Platform</h1>
<p class="lede">The platform finds newly published vulnerabilities, works out which of your GitHub repositories are affected, asks an LLM for the smallest
dependency fix, proves that fix inside a locked-down Docker sandbox, and opens a pull request. People review and merge it. The bot never merges.</p>
<div class="stats">{tiles}</div>
{suite_line}
</header>
{callout("", "How to use this document", "<p>Read <b>Status</b> and <b>Architecture</b> first (about 15 minutes). Then follow <b>Local setup</b> to get the tests green on your machine. "
 "<b>What is left</b> is the backlog, in priority order, and <b>Known issues</b> lists the traps that already cost time. The sections marked "
 "<i>generated</i> (settings, routes, tasks, schema, test counts) are read from the code, so regenerate the page with <code>python -m scripts.build_handover</code> after changing them.</p>")}"""


def status(f: dict[str, Any]) -> str:
    rows = [
        ["1 · CVE discovery", chip("done"), "NVD changes since a persisted cursor, enriched with OSV (OSV's package data lives in alias records such as GHSA, which are followed). "
         "Only CVEs touching a supported ecosystem are stored. KEV status comes from NVD's own fields. <b>Not built:</b> a separate GitHub Advisory DB client (an advisory webhook triggers a sync instead)."],
        ["1 · Triage", chip("done"), "CVSS bands, KEV flag, <code>MIN_CVSS_THRESHOLD</code>. KEV CVEs bypass the threshold (a deliberate deviation, see Decisions)."],
        ["2 · SBOM + matcher + repo filter", chip("done"), "Syft CycloneDX to S3 and PostgreSQL; version-range matcher that respects per-branch fixes; allow/block lists, archived and <code>cve-exempt</code> repos excluded; runtime override via the API."],
        ["3+4 · LangGraph fix agent", chip("partial", "Done for pip"), "All 15 nodes, the repair loop, reachability triage, pause/resume, checkpoint resume. <b>Only Python/pip is supported end to end.</b> npm, Go, Maven, NuGet and Gem are recognised by the SBOM and matcher but have no sandbox, test runner, installer or scanner target."],
        ["5 · PR + GitHub", chip("partial", "Done, no MCP"), "Atomic single-commit PRs, dedup guard, labels, CODEOWNERS reviewers, branch-protection report. Uses PyGithub behind an interface. <b>The GitHub MCP transport required by the locked design is not built.</b>"],
        ["6 · Notifications", chip("done"), "Teams, HMAC-signed webhook, SMTP email, PagerDuty (escalations at CVSS 9+). Idempotent per job, event and channel; every attempt logged."],
        ["7 · Tracking + audit", chip("done"), "Append-only audit trail, Confluence page per CVE and a daily page, JIRA ticket for Critical/High, confidence calibration from PR outcomes. <b>JIRA and Confluence have only ever run against mocks</b>, never a real tenant."],
        ["8 · Control plane", chip("done"), "Celery with four queues and the beat schedule from the spec; FastAPI Control API (every spec route, plus config GET and webhooks); per-repo locking; SLA escalation."],
    ]
    prod = [
        ["Security and access", chip("partial"), "API key, IP allowlist, HMAC webhooks, secret redaction, sandbox hardening, supply-chain version check: done. AWS Secrets Manager provider exists but was only tested against a fake client. IAM, mTLS and PAT rotation are infrastructure work."],
        ["Safety and governance", chip("done"), "Global kill-switch, bot never merges, branch protection is <i>reported</i> (not enforced by the bot)."],
        ["Observability", chip("todo"), "No CloudWatch metrics, X-Ray tracing, alarms or SLO catalogue. <code>CLOUDWATCH_NAMESPACE</code> and <code>XRAY_ENABLED</code> exist as settings but nothing reads them. Logging is structured JSON with <code>job_id</code> correlation."],
        ["CI/CD and infrastructure as code", chip("todo"), "No GitHub Actions, Terraform or Helm. The code is in git (public repository <code>priyanshu2510/SACVE</code>, branch <code>main</code>) but has no CI and no branch protection."],
        ["Quality and evaluation", chip("done"), "Golden-CVE evaluation harness with a release gate, and external-API contract tests including opt-in live checks. mypy/ruff gates (optional in the spec) are not set up."],
        ["Scale and idempotency", chip("done"), "Per-repo lock, cluster-wide sandbox cap (Redis), PR dedup, idempotency keys on every side effect, job-creation cap per run."],
        ["Data lifecycle", chip("partial"), "Keep-everything with mandatory redaction is implemented. Job logs are <b>not</b> written to S3 (<code>S3_BUCKET_LOGS</code> is unused). Backups and bucket versioning are infrastructure."],
    ]
    return section("status", "Status", f"""
<p>Every phase of the original specification exists and is tested. What is missing is mostly the work around the code: ecosystems beyond pip, the MCP transport, and everything needed to run it in AWS.</p>
<h3>By specification phase</h3>
{table(["Phase", "State", "What exists, and what does not"], rows)}
<h3>Production-readiness layer</h3>
{table(["Area", "State", "Detail"], prod)}
{callout("warn", "Nothing has run against your real systems yet", "<p>The internal LLM, Teams API, JIRA, Confluence, AWS and your GitHub organisation were all replaced by fakes or recorded shapes. "
 "The first job is to point the platform at real credentials and run the live checks (<b>Testing</b>, then <b>What is left</b>, P0). Expect to adjust: the LLM response schema, the Teams payload and auth header, JIRA priority and status names.</p>")}""")


def architecture(f: dict[str, Any]) -> str:
    v = f["versions"]
    steps = [
        "<b>06:00 UTC</b> <code>scan.sync_cves</code> reads NVD changes since the saved cursor, enriches each with OSV, and stores the ones that touch a supported ecosystem.",
        "<b>02:00 UTC</b> <code>scan.regenerate_sboms</code> syncs the organisation's repositories, then queues one <code>scan.generate_sbom</code> per in-scope repo (shallow clone, Syft, archive to S3, row in PostgreSQL).",
        "After either, the <b>matcher</b> evaluates every triaged CVE against every repo's newest SBOM, writes <code>cve_repo_impact</code>, creates one <code>QUEUED</code> job per CVE and repo (most urgent first, capped), and queues <code>remediation.run_fix_agent</code>.",
        "A remediation worker takes the <b>per-repo Redis lock</b>, claims the job (<code>QUEUED→RUNNING</code>), creates the Confluence page and JIRA ticket so the PR can link to them, then runs the graph.",
        "The <b>graph</b> assembles context, checks reachability, asks the LLM for a fix, scores it, validates it in a sandbox (baseline tests, patch, reinstall, tests again, vulnerability scan), and loops back to the LLM with the failure if any step fails.",
        "A fully validated fix becomes a <b>pull request</b> (one atomic commit, labels, CODEOWNERS reviewers). Owners are notified. <code>write_audit</code> persists the event trail and queues the Confluence/JIRA refresh.",
        "Reviewers act on GitHub. The <b>pull_request closed</b> webhook records the outcome (merged clean, merged with edits, closed unmerged), updates the job, notifies, and feeds the weekly confidence calibration.",
    ]
    stack = [
        ["Python", f["python"], "Everything. The sandbox image runs 3.12 too."],
        ["LangGraph", v["langgraph"], "The fix-agent state machine and its checkpoints"],
        ["langgraph-checkpoint-postgres", v["langgraph-checkpoint-postgres"], "Persists every graph step (<code>thread_id = job_id</code>)"],
        ["Celery + Redis", f'{v["celery"]} / redis-py {v["redis"]}', "Job queues, beat, locks, sandbox-slot semaphore"],
        ["FastAPI + uvicorn", f'{v["fastapi"]} / {v["uvicorn"]}', "Control API"],
        ["SQLAlchemy / Alembic / asyncpg", f'{v["sqlalchemy"]} / {v["alembic"]} / {v["asyncpg"]}', "ORM, migrations, async driver (psycopg " + v["psycopg"] + " for the checkpointer)"],
        ["Pydantic / pydantic-settings", f'{v["pydantic"]} / {v["pydantic-settings"]}', "All data models and typed configuration"],
        ["httpx", v["httpx"], "Every outbound HTTP call (LLM, NVD, OSV, Atlassian, notifications)"],
        ["PyGithub", v["PyGithub"], "GitHub reads and writes (paced; see Known issues)"],
        ["docker SDK", v["docker"], "Sandboxes"],
        ["Syft / Grype", "1.54.1 / 0.120.1", "SBOM generation (host) and vulnerability scanning (inside the sandbox image)"],
        ["boto3", v["boto3"], "S3 and AWS Secrets Manager"],
        ["structlog", v["structlog"], "JSON logs, <code>job_id</code> in every line of a job"],
        ["pytest / pytest-asyncio / jsonschema", f'{v["pytest"]} / {v["pytest-asyncio"]} / {v["jsonschema"]}', "Test stack"],
    ]
    return section("architecture", "Architecture", f"""
<p>Two cooperating pipelines share one database. The <b>detection pipeline</b> is ordinary Celery code. The <b>fix agent</b> is a LangGraph state machine that runs once per CVE and repository.</p>
{DG.architecture()}
<h3>End-to-end flow</h3>
<ol>{"".join(f"<li>{s}</li>" for s in steps)}</ol>
<h3>Technology (installed versions)</h3>
{table(["Component", "Version", "Used for"], stack, compact=True)}
{callout("", "Two design rules to keep", "<p><b>1. The LLM is used in exactly one place</b> (<code>generate_fix</code>). Everything else, including GitHub access, is deterministic code. "
 "<b>2. Nodes only return the fields they changed</b>; conditional edges are pure functions of the state. This is what makes every node unit-testable with a plain state object.</p>")}""")


def agent(f: dict[str, Any]) -> str:
    nodes = [
        ["assemble_context", "context_assembler.py", "Loads the CVE facts, <b>rejects a target version that is not an advisory fix</b> (supply-chain check), fetches the manifest, finds importing source files by code search (10 at most) and the release notes. Redacts secrets, then fits <code>LLM_CONTEXT_MAX_TOKENS</code>: CVE facts and manifest are never cut, source files next, changelog last.", "context_payload, context_token_count"],
        ["assess_reachability", "reachability.py", "pip only: AST scan of the fetched files for imports of the package. Concludes <i>unreachable</i> only when certain (direct dependency, complete search, no dynamic imports, no parse errors). <code>enforce</code> ends the job as NOT_REACHABLE; <code>advisory</code> annotates the PR.", "reachable, reachability_evidence"],
        ["generate_fix", "fix_generator.py", "The only LLM call. OpenAI-compatible JSON mode. Untrusted text is wrapped in <code>&lt;untrusted_data&gt;</code> tags that content cannot close. The answer must match the schema and pass path and content checks (below). Three tries on invalid output; API errors retried with backoff. Starts a new attempt and clears the previous attempt's results.", "file_changes, explanation, risk, self-confidence, fix_attempt"],
        ["score_confidence", "confidence_scorer.py", "Partial score (max 70) before any testing. Below 20 the job fails.", "confidence_score, breakdown"],
        ["run_sandbox", "sandbox_executor.py", "Starts the container, clones on the host and copies the repo in, creates the venv, installs the repo's current dependencies (the baseline). Removes the container itself if anything fails after creation.", "sandbox_container_id"],
        ["run_pre_tests", "test_runner.py", "Runs pytest on the untouched checkout. Failing tests end the job as BASELINE_FAILING; zero tests end it as NO_TESTS (<code>REQUIRE_TESTS</code>).", "pre_fix_tests"],
        ["apply_patch", "patch_applier.py", "Resets the workspace, then replaces each <code>original_content</code> with <code>new_content</code>, which must match exactly once. Files go in through a tar stream, never a shell.", "(failure → repair loop)"],
        ["resolve_dependencies", "dependency_resolver.py", "Reinstalls and verifies the vulnerable package really resolved to at least the target version.", "dependency_resolution_output, lockfile_changes"],
        ["run_post_tests", "test_runner.py", "Same suite after the patch. Any new failure or fewer passing tests is a regression. A clean run adds up to 25 points.", "post_fix_tests, test_delta_passed"],
        ["run_security_scan", "security_scanner.py", "Grype (offline, database baked into the image) over <code>/workspace</code> and the venv. The CVE id may appear as the vulnerability or as a related id. Resolved adds 5 points.", "scanner_cve_resolved, scanner_output"],
        ["cleanup_sandbox", "cleanup_sandbox.py", "Always removes the container and never raises. An exhausted repair loop becomes BLOCKED here.", "sandbox_container_id=None"],
        ["create_pr", "pr_creator.py", "Replays a recorded result for this job, or reuses an open bot PR for the same CVE, or creates the branch, atomic commit, PR, labels and review requests.", "branch_name, pr_url, pr_number, code_owners"],
        ["notify_owners", "notifier.py", "Fans out to the enabled channels. Delivery problems are recorded, never raised, because the PR already exists.", "notification_results"],
        ["write_audit", "audit_writer.py", "Writes the event trail and the job row in one transaction, once per run. <b>Deliberately not routed to handle_error</b>: if it fails the checkpoint stays before it and the Celery retry resumes exactly there.", "(none)"],
        ["handle_error", "handle_error.py", "Marks the job FAILED (also covers the low-confidence route) and hands on to cleanup.", "error, terminal_status=FAILED"],
    ]
    terminal = [
        ["PR_RAISED", "A validated fix became a PR (or an earlier PR from this same job was recovered).", "PR_RAISED"],
        ["PR_EXISTS", "An open bot PR for the same CVE already exists from another job. Nothing new is created or announced.", "PR_RAISED"],
        ["BLOCKED", "The repair loop ran out of attempts (patch does not apply, dependencies do not resolve, tests regress, or the CVE is still reported).", "BLOCKED"],
        ["BASELINE_FAILING", "The repository's own install or tests fail before any change.", "BLOCKED"],
        ["NO_TESTS", "The repository has no tests, so a fix cannot be validated.", "BLOCKED"],
        ["NOT_REACHABLE", "Reachability analysis proved the package is not used (enforce mode).", "NOT_REACHABLE"],
        ["FAILED", "An error: missing manifest, supply-chain mismatch, LLM unusable, sandbox or configuration problem, confidence below 20.", "FAILED"],
        ["DISABLED", "<code>AUTOMATION_ENABLED=false</code>: nothing ran.", "CANCELLED"],
        ["PAUSED", "Stopped on request between graph steps; resumable.", "PAUSED (set by the API)"],
    ]
    score = [
        ["CVE severity", "20", "<code>round(cvss / 10 × 20)</code>"],
        ["Fix simplicity", "25", "25 when only manifest or lock files change, 15 for config files, 5 for any code change"],
        ["LLM certainty", "15", "<code>round(self_confidence / 100 × 15)</code>"],
        ["Advisory fix known", "10", "The target version is one of the advisory's fix versions"],
        ["Test pass rate", "25", "Added after a regression-free post-fix run (scaled by pass ratio)"],
        ["Scanner confirmed", "5", "Added when grype no longer reports the CVE"],
    ]
    routers = [[code(n), esc(d)] for n, d in f["routers"]]
    return section("agent", "The fix agent", f"""
<p>Defined in <code>src/agent/graph.py</code>. State is a Pydantic model (<code>AgentState</code>) checkpointed to PostgreSQL after every step with <code>thread_id = job_id</code>.
Dashed nodes run inside the sandbox.</p>
{DG.agent()}
<h3>The repair loop</h3>
<p>This is what makes it an agent rather than a one-shot prompt. When the patch does not apply, dependencies do not resolve, tests regress, or the scanner still sees the CVE, the failing node records the reason and the router sends the run back to <code>generate_fix</code>.
The next prompt carries the previous attempts and their failure output (as untrusted data). The sandbox is reused and reset (<code>git checkout -- . && git clean -fd</code>). The limit is <code>MAX_FIX_ATTEMPTS</code> (default 3); after that the job ends BLOCKED and no PR is raised.</p>
<h3>Nodes</h3>
{table(["Node", "File (src/agent/nodes/)", "What it does", "Writes"], nodes, compact=True)}
<h3>Routing functions <span class="muted">(generated, src/agent/routing.py)</span></h3>
{table(["Function", "Rule"], routers, compact=True)}
<h3>How a run ends</h3>
{table(["terminal_status", "Meaning", "Job status"], [[code(a), b, code(c)] for a, b, c in terminal], compact=True)}
{DG.lifecycle()}
<h3>Confidence score</h3>
{table(["Component", "Max", "How it is computed"], score, compact=True, num_cols={1})}
<p>Tiers shown in the PR: <b>HIGH ≥ 85</b>, <b>MEDIUM ≥ 70</b>, otherwise LOW. These cut-offs are my own defaults (the spec names the tiers but not the numbers); the weekly calibration moves them once 30 reviewed PRs exist.</p>
<h3>Defences against hostile input</h3>
<p>CVE text, changelogs and repository files are attacker-influenceable, so:</p>
{ul([
    "Untrusted text is wrapped in <code>&lt;untrusted_data&gt;</code> tags; any tag the content tries to inject is escaped, and the system prompt says to treat the contents as data.",
    "Every file path the model returns must be inside the repo, free of <code>..</code> and absolute paths, on the list of files actually sent, and never under <code>.git/</code> or <code>.github/workflows/</code> (hard-denied even if allowlisted).",
    "<code>original_content</code> must appear exactly once in the file the model was shown; identical old and new content is rejected.",
    "Secrets are redacted before they reach the prompt, the state, the audit events, Confluence or the PR (<code>src/core/redaction.py</code>).",
    "The sandbox has no network and no credentials; the GitHub token is used only on the host.",
])}
<h3>Checkpoints, resume, pause</h3>
{ul([
    "A crash resumes from the last finished node. The runner resumes only when the checkpoint belongs to the <b>same <code>run_id</code></b>; a re-queued job gets a new <code>run_id</code> and starts fresh.",
    "<b>Pause</b> is cooperative: the runner checks the job status after each graph step, stops, removes the sandbox and rewinds to sandbox creation if the next step needed it. A long-running node delays a pause. <b>Resume</b> rebuilds the input from the stored <code>JOB_QUEUED</code> event.",
    "LangGraph's default recursion limit (25) is too low for three repair attempts, so <code>graph.RECURSION_LIMIT</code> is 100.",
])}""")
