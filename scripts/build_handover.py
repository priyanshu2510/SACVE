"""Build the hand-over document.

    python -m scripts.build_handover                          # writes docs/HANDOVER.html
    python -m scripts.build_handover --suite "818 passed in 75 s"
    python -m scripts.build_handover --fragment /tmp/page.html   # also write the embeddable fragment (no <html>/<head>/<body>)

Settings, routes, tasks, schema, test counts and the latest evaluation result are read from the code each time it runs,
so the generated sections cannot drift. The narrative lives in scripts/handover_{a,b,c}.py.
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

from scripts import handover_a as A
from scripts import handover_b as B
from scripts import handover_c as C
from scripts import handover_example as E
from scripts.handover_assets import CSS, FONTS, JS
from scripts.handover_lib import ROOT, esc, gather

NAV = [
    ("Orientation", [("overview", "What we are building"), ("status", "Status"), ("architecture", "Architecture"), ("example", "One CVE, end to end")]),
    ("How it works", [("agent", "The fix agent"), ("detection", "Detection pipeline"), ("services", "Services"), ("workers", "Workers and scheduling"),
                      ("api", "Control API"), ("data", "Data model"), ("config", "Configuration")]),
    ("Quality and safety", [("security", "Security model"), ("testing", "Testing and gates")]),
    ("Working on it", [("setup", "Local setup"), ("runbook", "Runbook"), ("howto", "How to change things")]),
    ("Decisions and backlog", [("decisions", "Decisions and deviations"), ("risks", "Known issues"), ("left", "What is left")]),
    ("Reference", [("map", "Repository map"), ("glossary", "Glossary")]),
]


def nav_html() -> str:
    out = []
    for group, items in NAV:
        out.append(f"<h2>{esc(group)}</h2>" + "".join(f'<a href="#{i}">{esc(t)}</a>' for i, t in items))
    return "".join(out)


def build(suite: str) -> str:
    f = gather()
    today = datetime.now(timezone.utc).strftime("%d %B %Y")
    sections = [
        E.overview(), A.status(f), A.architecture(f), E.example(f), A.agent(f), B.pipeline(f), B.services(), B.workers(f), B.api(f), B.data(f), B.config(f),
        C.security(), C.testing(f), C.setup(), C.runbook(), C.howto(), C.decisions(), C.risks(), C.backlog(), C.repo_map(), C.glossary(),
    ]
    ids = re.findall(r'<section id="([^"]+)"', "".join(sections))
    expected = [i for _g, items in NAV for i, _t in items]
    if ids != expected:
        raise SystemExit(f"section order does not match the navigation:\n  built    {ids}\n  expected {expected}")
    nav = nav_html()
    return f"""<title>CVE Remediation Handover</title>
{FONTS}
<style>{CSS}</style>
<div class="shell">
<aside class="rail" aria-label="Contents"><div class="brand">CVE Auto-Remediation</div><div class="sub">Hand-over · {esc(today)}</div>{nav}</aside>
<main>
<details class="rail-mobile"><summary>Contents</summary><nav>{"".join(f'<a href="#{i}">{esc(t)}</a>' for _g, items in NAV for i, t in items)}</nav></details>
{A.hero(f, today, suite)}
{"".join(sections)}
<footer>Generated {esc(today)} by <code>python -m scripts.build_handover</code>. Settings, routes, tasks, schema, test counts and evaluation results come from the code at build time; the rest is written by hand in <code>scripts/handover_*.py</code>.</footer>
</main>
</div>
<script>{JS}</script>
"""


def standalone(fragment: str) -> str:
    """Wrap the fragment as a complete document: title, fonts and styles belong in <head>, the rest in <body>."""
    split = fragment.index('<div class="shell">')
    head, body = fragment[:split], fragment[split:]
    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            + head + "</head>\n<body>\n" + body + "</body>\n</html>\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--suite", default="", help='result of the last full test run, e.g. "818 passed in 75 s"')
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "HANDOVER.html")
    parser.add_argument("--fragment", type=Path, help="also write the embeddable fragment here")
    args = parser.parse_args()
    fragment = build(args.suite)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(standalone(fragment))
    if args.fragment:
        args.fragment.write_text(fragment)
    print(f"wrote {args.out} ({len(fragment) // 1024} KB)")


if __name__ == "__main__":
    main()
