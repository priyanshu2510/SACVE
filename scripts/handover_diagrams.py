"""The diagrams of the hand-over document (inline SVG, theme-aware)."""

from __future__ import annotations

from scripts.handover_svg import Svg, figure


# ------------------------------------------------------------------------------------------------------ 1 · big picture
def overview() -> str:
    s = Svg(1200, 350, "From a published CVE to a reviewed pull request",
            "Six stages: discover CVEs, match them to repositories, an LLM proposes a fix, a sandbox proves it, a pull request is raised, a human merges. A failed proof loops back to the LLM.", "d-overview", 900)
    stages = [
        ("Discover", "New CVEs from NVD and OSV every day, and on GitHub advisories", ""),
        ("Match", "Which of your repositories use a vulnerable version? Uses SBOMs and version ranges", ""),
        ("Propose", "An LLM writes the smallest fix, usually a version bump", "io"),
        ("Prove", "Sandbox: baseline tests, patch, reinstall, tests again, vulnerability scan", "sb"),
        ("Raise", "One pull request per CVE and repo. CODEOWNERS review, JIRA ticket, Teams message", "io"),
        ("Human decides", "Review and merge. The bot never merges. The outcome tunes the next scores", "ok"),
    ]
    w, h, gap, x0, y = 168, 98, 30, 24, 96
    for i, (title, sub, kind) in enumerate(stages):
        x = x0 + i * (w + gap)
        s.box(x, y, w, h, title, sub, kind)
        s.badge(x + w - 18, y + 18, str(i + 1))
        if i < len(stages) - 1:
            s.arrow([(x + w, y + h / 2), (x + w + gap, y + h / 2)])
    x3, x4 = x0 + 2 * (w + gap) + w / 2, x0 + 3 * (w + gap) + w / 2
    s.arrow([(x4, y), (x4, 50), (x3, 50), (x3, y)], "fails? try again with the failure text · at most 3 attempts", (x3 + (x4 - x3) / 2, 40), "loop")
    x5, x6 = x0 + 4 * (w + gap) + w / 2, x0 + 5 * (w + gap) + w / 2
    s.arrow([(x6, y + h), (x6, 252), (x5, 252), (x5, y + h)], "merged / edited / rejected → confidence tiers", ((x5 + x6) / 2, 272), "soft")
    s.box(x4 - 150, 232, 300, 80, "Ends without a PR", "not reachable · baseline tests failing · repo has no tests · attempts used up (BLOCKED) · an error (FAILED)", "bad")
    s.arrow([(x4, y + h), (x4, 232)], kind="soft")
    s.text(600, 332, "Every step is written to an append-only audit trail · every side effect is idempotent · one switch (AUTOMATION_ENABLED) stops it all", "dg-s", "middle")
    return figure(s, "The whole system in one line: find the vulnerability, find who is affected, propose a fix, prove it works, ask humans to merge it.",
                  "Left to right is time. Blue boxes talk to an outside system (the LLM, GitHub). The dashed box runs in a locked-down Docker sandbox. The red dashed loop is the repair loop that makes this an agent rather than a one-shot prompt.")


# ------------------------------------------------------------------------------------------------------ 2 · architecture
def architecture() -> str:
    s = Svg(1200, 520, "System architecture", "Triggers feed Redis queues; Celery workers consume them, read and write PostgreSQL, S3 and Docker sandboxes, and call external services. GitHub sends webhooks back to the API.", "d-arch", 960)
    cols = [(16, 190, "Triggers"), (252, 190, "Redis"), (488, 250, "Celery workers"), (784, 180, "State"), (1000, 184, "External services")]
    for x, w, label in cols:
        s.group(x, 50, w, 420, label)
    iw, ih, y0, pitch = lambda w: w - 24, 66, 80, 74
    items = {
        0: [("Celery Beat", "scheduled jobs: SBOMs, CVE feed, pages, SLA", ""), ("Control API", "FastAPI · X-API-Key · jobs, scans, config", ""), ("GitHub webhooks", "push · PR closed · advisories · HMAC", "")],
        1: [("scanning", "CVE feed, SBOMs, matcher", ""), ("remediation", "one fix-agent run per job", "io"), ("notifications", "SLA escalation", ""), ("audit", "Confluence, JIRA, calibration", "")],
        2: [("Detection", "CVE sync → triage → SBOM → matcher → jobs", ""), ("Fix agent", "LangGraph, one run per CVE and repo, checkpointed, under a per-repo lock", "io"), ("Tracking and alerts", "Confluence, JIRA, SLA escalation, calibration", "")],
        3: [("PostgreSQL 16", "app tables, LangGraph checkpoints, audit trail", ""), ("S3 / MinIO", "versioned SBOM archive", ""), ("Docker sandboxes", "throw-away, no network", "sb")],
        4: [("NVD · OSV · PyPI", "public CVE feeds and registries", ""), ("GitHub", "clone, pull requests, code search", ""), ("Internal LLM", "OpenAI-compatible, JSON mode", ""), ("JIRA · Confluence", "tickets and audit pages", ""), ("Teams · PagerDuty · SMTP", "notifications", "")],
    }
    for ci, (x, w, _label) in enumerate(cols):
        for ri, (title, sub, kind) in enumerate(items[ci]):
            s.box(x + 12, y0 + ri * pitch, iw(w), ih, title, sub, kind)
    mid = 250
    s.arrow([(206, mid), (252, mid)], "enqueue", (229, mid - 8))
    s.arrow([(442, mid), (488, mid)], "consume", (465, mid - 8))
    s.arrow([(738, mid), (784, mid)], "read / write", (761, mid - 8), both=True)
    s.arrow([(613, 50), (613, 24), (1092, 24), (1092, 50)], "calls out over HTTPS", (853, 17), "soft")
    s.arrow([(1092, 470), (1092, 494), (111, 494), (111, 470)], "GitHub sends webhooks back: push, PR closed, advisories", (600, 510), "soft")
    return figure(s, "Two cooperating pipelines share one database: ordinary Celery detection code, and a LangGraph fix agent that runs once per CVE and repository.",
                  "Arrows go from the caller to the thing called. Dashed arrows are indirect (outbound calls, webhooks). Everything the system decides is written to PostgreSQL; Redis only carries work and locks.")


# ------------------------------------------------------------------------------------------------------ 3 · detection
def detection() -> str:
    s = Svg(1200, 430, "Detection pipeline", "Two scheduled flows, CVE feed at 06:00 and SBOMs at 02:00, meet in the matcher, which creates jobs and queues them for the fix agent.", "d-detect", 960)
    s.text(24, 34, "06:00 UTC · CVE feed", "dg-h")
    s.text(24, 164, "02:00 UTC · repository SBOMs", "dg-h")
    top = [("NVD changes", "modified since the saved cursor"), ("Enrich with OSV", "follow GHSA / GO / PYSEC aliases for packages and fixes"), ("Keep relevant", "only supported ecosystems are stored"), ("Triage", "CVSS bands, KEV first, drop below 4.0")]
    bot = [("Sync org repos", "allow / block lists, archived, cve-exempt"), ("Clone and Syft", "shallow clone → CycloneDX document"), ("Archive", "S3 (versioned) and the sboms table"), ("Parse components", "pinned versions in files a PR can edit")]
    w, h, gap, x0 = 200, 74, 30, 24
    for row, (items, y) in enumerate(((top, 48), (bot, 178))):
        for i, (t, sub) in enumerate(items):
            x = x0 + i * (w + gap)
            s.box(x, y, w, h, t, sub)
            if i < 3:
                s.arrow([(x + w, y + h / 2), (x + w + gap, y + h / 2)])
    mx = 940
    s.box(mx, 100, 236, 128, "Matcher", "Compares version ranges to every repo's newest SBOM, picks the smallest safe version (per-branch fixes respected), records cve_repo_impact", "io")
    s.arrow([(x0 + 3 * (w + gap) + w, 48 + h / 2), (904, 85), (904, 130), (mx, 130)], kind="")
    s.arrow([(x0 + 3 * (w + gap) + w, 178 + h / 2), (904, 215), (904, 190), (mx, 190)], kind="")
    s.box(mx, 262, 236, 76, "Job policy", "skip merged, blocked and in-flight · retry FAILED after 24 h · at most 50 new jobs per run", "")
    s.arrow([(mx + 118, 228), (mx + 118, 262)])
    s.box(mx, 366, 236, 50, "remediation queue", "one message per CVE and repo", "sb")
    s.arrow([(mx + 118, 338), (mx + 118, 366)])
    s.box(24, 288, 640, 70, "Shortcuts that skip the schedule", "push to a repo's default branch → refresh just that SBOM · security advisory published → run the CVE sync now · POST /api/v1/scan/... → manual scan", "mute")
    s.arrow([(664, 323), (mx, 323)], "same pipeline, sooner", (800, 316), "soft")
    return figure(s, "Detection runs on two clocks. The matcher is where a CVE becomes work: one job per CVE and repository, most urgent first.",
                  "Top lane: CVE feed. Bottom lane: repository inventory. Both end in the matcher. Messages are sent to the queue only after the database transaction commits, so a worker never sees a job that does not exist yet.")


# ------------------------------------------------------------------------------------------------------ 4 · the fix agent
def agent() -> str:
    s = Svg(1210, 640, "The fix-agent graph", "Fifteen nodes in three phases: prepare (context, reachability, LLM fix, score), validate inside a Docker sandbox, then deliver (cleanup, pull request, notifications, audit). Any validation failure loops back to the LLM.", "d-agent", 1000)
    w, h = 270, 66
    c1, c2, c3 = 40, 470, 900
    s.group(c2 - 14, 44, w + 28, 566, "Inside the Docker sandbox", "sb")
    s.text(c1, 34, "Prepare", "dg-h")
    s.text(c3, 34, "Deliver", "dg-h")
    ys = [64, 142, 220, 298, 376, 454]
    col1 = [("assemble_context", "CVE facts, manifest, importing files", "supply-chain mismatch → FAILED", ""), ("assess_reachability", "is the package actually used?", "unused (enforce) → NOT_REACHABLE", ""),
            ("generate_fix", "the only LLM call", "unusable output → FAILED", "io"), ("score_confidence", "partial score, at most 70", "score below 20 → FAILED", "")]
    col2 = [("run_sandbox", "create container, clone, baseline install", "install fails → BASELINE_FAILING", ""), ("run_pre_tests", "the repo's own tests, untouched", "failing → BASELINE_FAILING · none → NO_TESTS", ""),
            ("apply_patch", "exactly-one-match replacement", "", ""), ("resolve_dependencies", "reinstall; version must reach target", "", ""),
            ("run_post_tests", "no new failures (+25 points)", "", ""), ("run_security_scan", "Grype: the CVE must be gone (+5)", "", "")]
    col3 = [("cleanup_sandbox", "always removes the container", "attempts used up → BLOCKED", ""), ("create_pr", "atomic commit, labels, reviewers", "open bot PR exists → skip", "io"),
            ("notify_owners", "Teams, webhook, email", "never fails the job", ""), ("write_audit", "events and job row, once", "failure → retry resumes here", "")]
    for col, x in ((col1, c1), (col2, c2), (col3, c3)):
        for i, (t, sub, tag, kind) in enumerate(col):
            s.box(x, ys[i], w, h, t, sub, kind, tag, mono=True)
            if i < len(col) - 1:
                s.arrow([(x + w / 2, ys[i] + h), (x + w / 2, ys[i + 1])])
    s.arrow([(c1 + w, ys[3] + h / 2), (c1 + w + 55, ys[3] + h / 2), (c1 + w + 55, ys[0] + h / 2), (c2, ys[0] + h / 2)])
    s.arrow([(c2 + w, ys[5] + h / 2), (c2 + w + 60, ys[5] + h / 2), (c2 + w + 60, ys[0] + h / 2), (c3, ys[0] + h / 2)], "validated", (c2 + w + 62, ys[5] + h / 2 - 8), anchor="start")
    # repair loop: bus on the left edge of the sandbox group, back to generate_fix
    bus_x = c2 - 30
    for i in (2, 3, 4, 5):
        s.arrow([(c2, ys[i] + h / 2), (bus_x, ys[i] + h / 2)], kind="loop", head=False)
    s.arrow([(bus_x, ys[5] + h / 2), (bus_x, ys[2] + h / 2), (c1 + w, ys[2] + h / 2)], kind="loop")
    s.text(c1 + w + 6, ys[5] + h / 2 + 30, "any failure = repair loop", "dg-lbl")
    s.text(c1 + w + 6, ys[5] + h / 2 + 44, "(at most 3 attempts; the failure", "dg-lbl")
    s.text(c1 + w + 6, ys[5] + h / 2 + 58, "text goes back to the LLM)", "dg-lbl")
    s.box(c3, 454, w, 66, "handle_error", "any unexpected error → FAILED, then cleanup", "bad", mono=True)
    s.arrow([(c3 + w, 487), (1192, 487), (1192, ys[0] + h / 2), (c3 + w, ys[0] + h / 2)], "any error", (1180, 300), "soft", anchor="end")
    s.text(c3, 548, "Every path ends in write_audit. It is not routed to", "dg-s")
    s.text(c3, 562, "handle_error: if it fails, the Celery retry resumes", "dg-s")
    s.text(c3, 576, "exactly there.", "dg-s")
    return figure(s, "The 15 nodes of src/agent/graph.py. Red tags show how a run can end without a PR.",
                  "Read each column top to bottom. Solid arrows are the happy path. The red dashed line is the repair loop: when the patch will not apply, the install conflicts, tests regress or the scanner still sees the CVE, the run returns to generate_fix with the failure attached. Blue nodes talk to an external system.")


# ------------------------------------------------------------------------------------------------------ 5 · sandbox anatomy
def sandbox() -> str:
    s = Svg(1100, 500, "Sandbox anatomy", "The worker host clones the repository and streams it into a read-only container with no network; only text output comes back. Installs reach the package registry through an allowlisting proxy.", "d-sandbox", 900)
    s.box(330, 2, 470, 50, "Cluster-wide slot lease", "MAX_CONCURRENT_SANDBOXES, held in Redis", "mute")
    s.group(16, 56, 270, 400, "Worker host")
    hosts = [("git clone (shallow)", "the token is passed through git's environment, never argv or .git/config"), ("tar the checkout", "files owned by uid 1000"), ("docker exec tar -x", "streamed over stdin, because put_archive is refused on read-only roots")]
    for i, (t, sub) in enumerate(hosts):
        s.box(28, 90 + i * 92, 246, 78, t, sub)
        if i < 2:
            s.arrow([(151, 168 + i * 92), (151, 182 + i * 92)])
    s.group(330, 56, 470, 400, "Sandbox container", "sb")
    inner = [("/workspace (tmpfs, 512 MB)", "the repository; reset with git between attempts"), ("/opt/venv (tmpfs, 768 MB)", "pip install of the repo's dependencies plus pytest"), ("Grype + vulnerability database", "baked into the image; scanning is offline")]
    for i, (t, sub) in enumerate(inner):
        s.box(348, 90 + i * 76, 434, 64, t, sub, mono=True)
    s.text(348, 336, "Runs only: pytest · pip · grype · git", "dg-t")
    s.text(348, 360, "uid 1000 · cap_drop ALL · no-new-privileges · read-only root", "dg-s")
    s.text(348, 376, "2 GB RAM, no swap · 0.5 CPU · 256 processes · per-command timeout", "dg-s")
    s.text(348, 392, "no Docker socket · no host mounts · no credentials inside", "dg-s")
    s.text(348, 424, "Removed in cleanup_sandbox, always. A crashed run's container is", "dg-s")
    s.text(348, 438, "found by its job_id label and removed the next time.", "dg-s")
    s.arrow([(274, 290), (330, 290)], "files in", (302, 281))
    s.arrow([(330, 322), (274, 322)], "text only", (302, 346), "soft")
    s.group(850, 56, 234, 400, "Network")
    s.box(862, 90, 210, 62, "Open internet", "no route from the container", "bad")
    s.arrow([(800, 121), (862, 121)], kind="block", head=False)
    s.cross(831, 121)
    s.box(862, 214, 210, 62, "Internal egress network", "only used for installs", "")
    s.box(862, 292, 210, 62, "Allowlisting proxy", "SANDBOX_NETWORK_MODE = registry-allowlist", "")
    s.box(862, 370, 210, 62, "Package registry", "PyPI or your internal index", "")
    s.arrow([(800, 245), (862, 245)], "installs", (831, 236), "soft")
    s.arrow([(967, 276), (967, 292)])
    s.arrow([(967, 354), (967, 370)])
    return figure(s, "What \"locked down\" means here. The repository goes in by stream, results come out as text, and the only network path leads to the package registry.",
                  "The default network mode is none: nothing can be installed, so nothing can be validated. Production needs the internal network and the proxy (listed in What is left); the manager refuses a network that is not internal.")


# ------------------------------------------------------------------------------------------------------ 6 · job lifecycle
def lifecycle() -> str:
    s = Svg(1100, 470, "Job lifecycle", "A job starts QUEUED, is claimed to RUNNING, and ends PR_RAISED then MERGED, or BLOCKED, FAILED, NOT_REACHABLE or CANCELLED. It can be paused and resumed. FAILED jobs are re-queued after 24 hours.", "d-life", 900)
    w, h = 160, 50
    boxes = {
        "QUEUED": (40, 160, "waiting for a worker", ""), "RUNNING": (300, 160, "the graph is running", ""), "PAUSED": (300, 40, "stopped between steps", "warn"),
        "PR_RAISED": (710, 40, "PR waiting for review", "io"), "MERGED": (940, 40, "final", "ok"), "BLOCKED": (710, 160, "final: rejected or unsafe", "warn"),
        "FAILED": (710, 270, "an error; retryable", "bad"), "NOT_REACHABLE": (710, 380, "final: package unused", "warn"), "CANCELLED": (40, 380, "final: cancelled", "mute"),
    }
    for name, (x, y, sub, kind) in boxes.items():
        s.box(x, y, w, h, name, sub, kind, mono=True)
    s.arrow([(200, 185), (300, 185)], "worker claims", (250, 177))
    s.arrow([(70, 210), (70, 380)], "DELETE job", (78, 300), anchor="start")
    s.arrow([(340, 160), (340, 90)], "pause", (348, 130), anchor="start")
    s.arrow([(300, 62), (110, 62), (110, 160)], "resume (from the checkpoint)", (205, 54))
    s.arrow([(460, 172), (540, 172), (540, 62), (710, 62)], "validated fix → PR", (548, 112), anchor="start")
    s.arrow([(460, 190), (710, 190)], "attempts used up · baseline · no tests", (470, 184), anchor="start")
    s.arrow([(460, 205), (520, 205), (520, 310), (710, 310)], "error", (528, 262), anchor="start")
    s.arrow([(380, 216), (380, 410), (710, 410)], "unused package (enforce mode)", (388, 402), anchor="start")
    s.arrow([(870, 65), (940, 65)], "merged", (905, 57))
    s.arrow([(790, 96), (790, 160)], "closed unmerged", (798, 133), anchor="start")
    s.arrow([(710, 282), (150, 282), (150, 216)], "after 24 h the matcher re-queues it", (330, 274), "soft")
    s.text(40, 466, "A QUEUED job older than 6 hours is re-sent (its broker message was lost). MERGED, BLOCKED, NOT_REACHABLE and CANCELLED are never touched again.", "dg-s")
    return figure(s, "Job states in remediation_jobs. The transitions people ask about most are pause, resume and the automatic retry of failed jobs (dashed).",
                  "Only RUNNING jobs can be paused and only PAUSED jobs resumed; anything else returns 409. Rejecting a PR on GitHub makes the job BLOCKED, so the bot never raises that fix again.")


# ------------------------------------------------------------------------------------------------------ 7 · feedback loop
def feedback() -> str:
    s = Svg(1000, 440, "Human feedback loop", "A raised pull request is reviewed by people, the webhook records the outcome with the predicted confidence, and a weekly job moves the confidence tier thresholds that appear in the next pull requests.", "d-feedback", 820)
    w, h = 260, 88
    s.box(24, 30, w, h, "Bot raises the PR", "shows confidence, e.g. 90 / 100 = HIGH", "io")
    s.box(370, 30, w, h, "Code owners review", "on GitHub, with CODEOWNERS and branch protection", "ok")
    s.box(716, 30, w, h, "Webhook records the outcome", "pr_outcomes row with the predicted score; job becomes MERGED or BLOCKED; JIRA and Teams updated", "")
    s.arrow([(24 + w, 74), (370, 74)], "opens", (327, 66))
    s.arrow([(370 + w, 74), (716, 74)], "PR closed", (673, 66))
    outs = [("Merged clean", "bot's single commit", "ok"), ("Merged with edits", "extra commits added", "warn"), ("Closed unmerged", "rejected: never re-raised", "bad")]
    for i, (t, sub, kind) in enumerate(outs):
        x = 330 + i * 118
        s.box(x, 160, 112, 86, t, sub, kind)
        s.arrow([(x + 56, 160), (x + 56, 118)], head=False, kind="soft")
    s.arrow([(846, 118), (846, 266)], "weekly", (854, 200), anchor="start")
    s.box(716, 266, w, h + 10, "Weekly calibration", "lowest score whose own band was merged clean ≥ 90% (HIGH) and ≥ 70% (MEDIUM); needs 30 reviewed PRs", "")
    s.box(370, 266, w, h + 10, "New thresholds stored", "sync_state: confidence_calibration; defaults 85 / 70 until there is data", "")
    s.arrow([(716, 303), (630, 303)])
    s.box(24, 266, w, h + 10, "Next PRs use the new tiers", "so HIGH means what reviewers actually accepted", "io")
    s.arrow([(370, 303), (284, 303)])
    s.arrow([(154, 266), (154, 118)], "feeds back", (162, 200), "soft", anchor="start")
    s.text(24, 402, "A PR is attributed to a job only if its branch prefix, the hidden body marker, the repository and the PR number all match.", "dg-s")
    return figure(s, "How reviewers teach the system. The platform learns what its confidence score is worth from what people do with the PRs.",
                  "It is a cycle: start at the blue box, follow the arrows right, then down, then left, and back up.")
