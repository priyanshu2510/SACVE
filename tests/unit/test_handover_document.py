"""The hand-over document must keep building: a new setting without a description, a renamed section, or a map entry for a
deleted path fails here instead of silently leaving the document stale."""

import re
from html.parser import HTMLParser

import pytest

from scripts.build_handover import NAV, build, standalone


class _Check(HTMLParser):
    VOID = {"meta", "link", "br", "hr", "img", "input"}

    def __init__(self):
        super().__init__()
        self.stack, self.ids, self.hrefs, self.problems = [], [], [], []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if "id" in d:
            self.ids.append(d["id"])
        if tag == "a" and d.get("href", "").startswith("#"):
            self.hrefs.append(d["href"][1:])
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.problems.append(f"</{tag}> closes {self.stack[-1:]}")
        elif self.stack:
            self.stack.pop()


@pytest.fixture(scope="module")
def page() -> str:
    return build("")


def test_builds_and_is_well_formed(page):
    check = _Check()
    check.feed(page)
    assert not check.problems and not check.stack
    assert len(check.ids) == len(set(check.ids)), "duplicate element ids"
    assert [h for h in check.hrefs if h not in check.ids] == [], "a contents link points nowhere"


def test_every_navigation_entry_has_a_section(page):
    for _group, items in NAV:
        for section_id, _title in items:
            assert f'<section id="{section_id}"' in page


def test_no_unrendered_template_text(page):
    assert "{{" not in page and "}}" not in page and "Traceback" not in page
    assert not re.search(r">\s*None\s*<", page), "a Python None leaked into a cell or element"


def test_generated_facts_are_present(page):
    for needle in ("scan.sync_cves", "remediation_jobs", "AUTOMATION_ENABLED", "POST /api/v1", "/api/v1/jobs/{job_id}/graph-trace"):
        assert needle in page or needle.replace("POST ", "") in page


def test_standalone_wrapper_is_a_complete_document(page):
    doc = standalone(page)
    assert doc.startswith("<!doctype html>") and "viewport" in doc and doc.rstrip().endswith("</html>")
    assert len(re.findall(r"<title>", doc)) == 1
    head = doc[doc.index("<head>"):doc.index("</head>")]
    assert "<title>" in head and "<style>" in head and "fonts.googleapis.com" in head  # not stranded in <body>
    assert "<script>" not in head and doc.index("</head>") < doc.index('<div class="shell">')


def test_diagrams_are_well_formed_and_accessible(page):
    import xml.etree.ElementTree as ET

    svgs = re.findall(r"<svg class=\"dg\".*?</svg>", page, flags=re.S)
    assert len(svgs) >= 7, "expected the overview, architecture, detection, agent, sandbox, lifecycle and feedback diagrams"
    for svg in svgs:
        root = ET.fromstring(svg)  # raises on malformed markup
        ns = "{http://www.w3.org/2000/svg}"
        assert root.find(f"{ns}title") is not None and root.find(f"{ns}desc") is not None
        ids = [m.get("id") for m in root.iter(f"{ns}marker")]
        used = set(re.findall(r"url\(#([^)]+)\)", svg))
        assert used <= set(ids), f"arrow marker without a definition: {used - set(ids)}"
    uids = re.findall(r"<title id=\"([^\"]+)\"", page)
    assert len(uids) == len(set(uids)), "diagram ids must be unique across the page"
    assert page.count("<figcaption>") == page.count('<figure class="figure">')
