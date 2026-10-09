"""Run the golden-CVE evaluation and apply the release gate.

    python -m tests.eval.run                       # replay mode (recorded model answers)
    python -m tests.eval.run --mode live           # your configured LLM
    python -m tests.eval.run --cases bump_requests,prompt_injection --report eval-report.json

Exit code 0 = gate passed, 1 = gate failed. Needs Docker, the sandbox image and network access to PyPI.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from tests.eval.harness import DEFAULT_IMAGE, evaluate_gate, load_cases, render_report, report_json, run_case


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["replay", "live"], default="replay")
    parser.add_argument("--cases", help="comma-separated case names (default: all)")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="sandbox image")
    parser.add_argument("--report", type=Path, help="write a JSON report here")
    args = parser.parse_args(argv)

    cases = load_cases(args.cases.split(",") if args.cases else None)
    results = []
    for case in cases:  # sequential: each case uses a sandbox and the shared LLM budget
        print(f"running {case.name} ...", flush=True)
        results.append(await run_case(case, args.mode, args.image))
    gate = evaluate_gate(results, args.mode)
    print("\n" + render_report(results, gate))
    if args.report:
        args.report.write_text(json.dumps(report_json(results, gate, args.mode), indent=2, default=str))
    return 0 if gate.passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
