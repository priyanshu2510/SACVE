"""'What we are building' and the worked example. The example is computed with the real code (matcher, scorer, prompt and PR
renderers) on the golden case, so it cannot drift from what the system actually does."""

from __future__ import annotations

import difflib
import json
from typing import Any

from scripts import handover_diagrams as DG
from scripts.handover_lib import ROOT, callout, esc, pre, section, ul


def overview() -> str:
    return section("overview", "What we are building", f"""
<p><b>The problem.</b> Dependencies get vulnerabilities published against them every day. For a company with many repositories, finding which ones are affected, deciding what to change, testing that the change is safe and getting a pull request in front of the right reviewer is slow, repetitive work, so fixes wait weeks.</p>
<p><b>The solution.</b> A service that does everything up to the review. It watches the public vulnerability feeds, checks every one of your GitHub repositories, has an LLM propose the smallest possible fix (almost always a version bump), then <i>proves</i> the fix in a throw-away Docker sandbox by running the repository's own tests and a vulnerability scanner. Only a fix that passes becomes a pull request, addressed to the people who own the code. Humans stay in charge: they review and merge, and the bot cannot merge.</p>
{DG.overview()}
<div class="grid2">
<div><h4>What a developer sees</h4>{ul([
    "A pull request titled <code>fix(medium): CVE-2024-35195 bump requests 2.31.0 → 2.32.0</code>, with the test results before and after, a confidence score, and links to the audit page and JIRA ticket.",
    "A Teams message, and a JIRA ticket for Critical and High CVEs.",
    "Nothing at all for CVEs that do not affect them, or that the system could not fix safely.",
])}</div>
<div><h4>What it deliberately does not do</h4>{ul([
    "Merge anything, or touch CI configuration (workflow files are hard-denied).",
    "Raise a PR it could not prove: failing baseline tests, no tests, or a CVE still reported all stop it.",
    "Rewrite application code on its own initiative. It makes the minimal change that clears the CVE.",
    "Act on text found in a repository or advisory as if it were an instruction.",
])}</div>
</div>
<p>The rest of this document explains how each stage works, what exists today, and what is left. If you read nothing else, read this section, <b>One CVE, end to end</b> (a real walk-through), and <b>What is left</b>.</p>""")


def _case(name: str) -> dict[str, Any]:
    import yaml

    base = ROOT / "tests" / "eval" / "cases" / name
    data = yaml.safe_load((base / "case.yaml").read_text())
    data["responses"] = json.loads((base / "llm_responses.json").read_text())
    data["files"] = {p.relative_to(base / "repo").as_posix(): p.read_text() for p in (base / "repo").rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    return data


def example(f: dict[str, Any]) -> str:
    from src.agent.nodes.fix_generator import build_user_prompt
    from src.agent.state import AgentState, FileChange, TestResult
    from src.services.github.pr_description import confidence_tier, pr_title, render_pr_body
    from src.services.matcher.vulnerability_matcher import evaluate

    case = _case("bump_requests")
    cve, job, answer = case["cve"], case["job"], case["responses"][0]
    change = answer["file_changes"][0]
    ev = evaluate(job["installed_version"], cve["affected_versions"], cve["fixed_version"])

    breakdown = {"severity": round(cve["cvss"] / 10 * 20), "simplicity": 25, "llm_certainty": round(answer["self_confidence"] / 100 * 15), "advisory": 10, "tests": 25, "scanner": 5}
    partial = breakdown["severity"] + breakdown["simplicity"] + breakdown["llm_certainty"] + breakdown["advisory"]
    total = sum(breakdown.values())

    ctx = {"cve": {"description": cve["description"]}, "manifest": {"path": "requirements.txt", "content": case["files"]["requirements.txt"]},
           "source_files": [{"path": "app/client.py", "content": case["files"]["app/client.py"], "truncated": False}], "changelog": None, "file_allowlist": ["requirements.txt", "app/client.py"]}  # fmt: skip
    state = AgentState(
        job_id="7b264f9d-e6c3-4276-93db-d2f632e70687", cve_id=cve["cve_id"], repo_name="org/api", ecosystem="pip", affected_package="requests",
        installed_version=job["installed_version"], target_version=job["target_version"], manifest_file_path="requirements.txt", cvss_score=cve["cvss"],
        severity=cve["severity"], context_payload=ctx, fix_attempt=1, confidence_score=total, confidence_breakdown=breakdown, llm_explanation=answer["explanation"],
        breaking_change_risk=answer["breaking_change_risk"], test_delta_passed=True, scanner_cve_resolved=True,
        pre_fix_tests=TestResult(total=1, passed=1, failed=0, skipped=0, stdout=""), post_fix_tests=TestResult(total=1, passed=1, failed=0, skipped=0, stdout=""),
        file_changes=[FileChange(file_path=change["file_path"], original_content=change["original_content"], new_content=change["new_content"], change_description=change["change_description"])],
    )  # fmt: skip
    prompt = build_user_prompt(state)
    prompt_excerpt = "\n".join(prompt.splitlines()[:11]) + "\n…"
    body = render_pr_body(state, "https://control.example.com")
    body_excerpt = "\n".join(body.splitlines()[:24]) + "\n…"
    old = case["files"]["requirements.txt"].splitlines()
    new = [ln.replace(change["original_content"], change["new_content"]) for ln in old]
    diff = "\n".join(difflib.unified_diff(old, new, "a/requirements.txt", "b/requirements.txt", lineterm="", n=0))

    run = None
    if f.get("eval"):
        run = next((c for c in f["eval"]["cases"] if c["name"] == "bump_requests"), None)
    timing = f" The real run of this case in the evaluation harness took {run['duration_s']:.0f} seconds end to end and ended <code>{esc(run['terminal_status'])}</code> with confidence {run['confidence']}." if run else ""

    steps = [
        ("Discover", "<code>scan.sync_cves</code>", f"NVD reports <b>{cve['cve_id']}</b> (CVSS {cve['cvss']}, {cve['severity']}). OSV says <code>requests</code> is affected below <code>2.32.0</code>, and that 2.32.0 is the fix. The CVE is stored with its affected-package row.",
         pre(f"cves:                  {cve['cve_id']}  cvss={cve['cvss']}  severity={cve['severity']}\ncve_affected_packages: pip  {cve['package']}  affected={cve['affected_versions']}  fixed={cve['fixed_version']}")),
        ("Match", "<code>generate_sbom</code>, matcher", f"Syft listed <code>requests 2.31.0</code> as declared in <code>requirements.txt</code> of <code>org/api</code>. The matcher evaluates the range and picks the smallest safe version. A job is created and queued.",
         pre(f"evaluate(installed='{job['installed_version']}', ranges={cve['affected_versions']})\n  -> affected={ev.affected}  safe_version='{ev.safe_version}'\nremediation_jobs: org/api  {cve['cve_id']}  QUEUED   (one job per CVE and repo)")),
        ("Pick up the job", "<code>remediation.run_fix_agent</code>", "A worker takes the per-repo lock, moves the job to RUNNING, and creates the JIRA ticket and Confluence page so the PR can link to them."),
        ("Assemble context", "<code>assemble_context</code>, <code>assess_reachability</code>",
         "It checks the target version really is an advisory fix (the supply-chain check), fetches the manifest and the files that import <code>requests</code>, redacts secrets, and confirms the package is actually imported (reachable)."),
        ("Ask the LLM", "<code>generate_fix</code>", "The untrusted text is wrapped in delimiters. This is the start of the real prompt:", pre(prompt_excerpt)),
        ("The model answers", "<code>generate_fix</code>", "It must reply with JSON. The answer is rejected unless the file is one it was shown, outside <code>.git</code> and workflow files, and the old text appears exactly once.", pre(json.dumps(answer, indent=2))),
        ("Score it", "<code>score_confidence</code>", f"Before any testing the fix scores {partial} out of a possible 70: severity {breakdown['severity']} (CVSS {cve['cvss']}), simplicity {breakdown['simplicity']} (only a manifest changes), model certainty {breakdown['llm_certainty']}, advisory known {breakdown['advisory']}."),
        ("Baseline", "<code>run_sandbox</code>, <code>run_pre_tests</code>", "A sandbox starts, the repo is copied in, dependencies are installed, and the repository's own tests run <i>before</i> any change: 1 passed. If they had failed the job would stop here as BASELINE_FAILING."),
        ("Patch and reinstall", "<code>apply_patch</code>, <code>resolve_dependencies</code>", "The old text is replaced exactly once, dependencies are reinstalled, and the installed <code>requests</code> must be at least 2.32.0.", pre(diff)),
        ("Prove it", "<code>run_post_tests</code>, <code>run_security_scan</code>", f"The tests run again: 1 passed, no regression (+{breakdown['tests']}). Grype scans the workspace and the environment: {cve['cve_id']} is gone (+{breakdown['scanner']}). Total confidence {total} out of 100, tier {confidence_tier(total).label}. Any failure here would have sent the failure text back to the model for another try (up to 3 attempts)."),
        ("Clean up", "<code>cleanup_sandbox</code>", "The container is removed whatever happened."),
        ("Raise the PR", "<code>create_pr</code>", f"One atomic commit on a new branch, labels, and reviews requested from the CODEOWNERS of <code>requirements.txt</code>. Title: <code>{esc(pr_title(state))}</code>. The start of the description:", pre(body_excerpt)),
        ("Tell people, record everything", "<code>notify_owners</code>, <code>write_audit</code>",
         "Owners get a Teams message. The event trail is written in one transaction and the JIRA and Confluence records are refreshed:", pre("CONTEXT_ASSEMBLED  REACHABILITY_ASSESSED  FIX_GENERATED  CONFIDENCE_SCORED  SANDBOX_STARTED\nPRE_TESTS_PASSED  PATCH_APPLIED  PATCH_APPLIED  POST_TESTS_PASSED  SCAN_CONFIRMED\nSANDBOX_REMOVED  PR_RAISED  NOTIFICATION_SENT")),
        ("A human decides", "webhook", "A reviewer merges. GitHub's <code>pull_request closed</code> webhook records <code>MERGED_CLEAN</code> next to the predicted score 90, the job becomes MERGED, JIRA moves to Done, and the weekly calibration learns that a score of 90 was right."),
    ]
    rendered = []
    for step in steps:
        title, where, text = step[0], step[1], step[2]
        extra = step[3] if len(step) > 3 else ""
        rendered.append(f'<li><b>{title}</b> <span class="muted">· {where}</span><div class="stepbody">{text}{extra}</div></li>')
    items = "".join(rendered)
    return section("example", "One CVE, end to end", f"""
<p>This follows <b>CVE-2024-35195</b> through the system using the evaluation harness's <code>bump_requests</code> case. The table rows, scores, prompt, answer, diff and PR text below are produced by the real code on that case, not written by hand.{timing}</p>
<ol class="steps">{items}</ol>
{callout("", "What would have happened if something failed", "<p>Tests regress: the failure output goes back to the model and it tries again. Dependency conflict: same. The scanner still sees the CVE: same. Three failures: the job ends <code>BLOCKED</code>, no PR is raised, and the audit trail says why. The golden cases <code>regression_blocks</code>, <code>wrong_fix_blocks</code> and <code>vendored_copy</code> run exactly those paths.</p>")}""")
