import pytest

from src.agent.nodes import context_assembler as ca
from src.agent.nodes.context_assembler import assemble_context, estimate_tokens, truncate_to_tokens
from tests.conftest import FakeContentSource

MANIFEST = "flask==3.0.0\nrequests==2.31.0\n"
APP = "import requests\n\ndef get():\n    return requests.get('https://x')\n"


def source(**kw):
    base = dict(
        files={"requirements.txt": MANIFEST, "app/client.py": APP},
        search={"requests": ["app/client.py", "requirements.txt"]},
        release_notes="## 2.32.0\n- fix verify=False",
    )
    base.update(kw)
    return FakeContentSource(**base)


def test_estimate_and_truncate_helpers():
    assert estimate_tokens("a" * 8) == 2 and estimate_tokens("") == 0
    text, cut = truncate_to_tokens("line1\nline2\nline3\n" * 10, 5)
    assert cut and len(text) <= 20 and not text.endswith("\n") or text == ""
    assert truncate_to_tokens("short", 100) == ("short", False)


async def test_happy_path(make_state, agent_deps):
    with agent_deps(source()):
        out = await assemble_context(make_state())
    p = out["context_payload"]
    assert "error" not in out
    assert p["manifest"] == {"path": "requirements.txt", "content": MANIFEST}
    assert [f["path"] for f in p["source_files"]] == ["app/client.py"]  # manifest excluded from sources
    assert p["file_allowlist"] == ["requirements.txt", "app/client.py"]
    assert p["cve"]["advisory_fix_verified"] is True and p["cve"]["fixed_versions"] == ["2.32.0"]
    assert p["changelog"].startswith("## 2.32.0")
    assert p["manifest_declares_package"] is True and p["source_search_complete"] is True
    assert out["context_token_count"] == sum(
        estimate_tokens(x) for x in [MANIFEST, APP, p["changelog"]]
    ) + estimate_tokens(__import__("json").dumps(p["cve"]))
    assert out["audit_events"][-1]["event_type"] == "CONTEXT_ASSEMBLED"


async def test_unknown_cve_is_an_error(make_state, agent_deps):
    from src.agent.deps import override_deps

    async def none_loader(*a):
        return None

    with override_deps(content_source=source(), cve_loader=none_loader):
        out = await assemble_context(make_state())
    assert "not found in the CVE database" in out["error"] and out["terminal_status"] == "FAILED"


async def test_supply_chain_mismatch_blocks(make_state, agent_deps):
    with agent_deps(source()):
        out = await assemble_context(make_state(target_version="2.99.0"))
    assert "supply-chain check failed" in out["error"]


async def test_supply_chain_check_can_be_disabled(make_state, agent_deps, monkeypatch):
    monkeypatch.setattr(ca.settings, "SUPPLY_CHAIN_VERIFY", False)
    with agent_deps(source()):
        out = await assemble_context(make_state(target_version="2.99.0"))
    assert "error" not in out and out["context_payload"]["cve"]["advisory_fix_verified"] is False


async def test_equivalent_version_spellings_pass(make_state, agent_deps):
    with agent_deps(source()):
        out = await assemble_context(make_state(target_version="v2.32"))
    assert "error" not in out


async def test_missing_manifest(make_state, agent_deps):
    with agent_deps(source(files={})):
        out = await assemble_context(make_state())
    assert "manifest requirements.txt not found" in out["error"]


async def test_fixed_part_over_budget_fails(make_state, agent_deps, monkeypatch):
    monkeypatch.setattr(ca.settings, "LLM_CONTEXT_MAX_TOKENS", 20)
    with agent_deps(source()):
        out = await assemble_context(make_state())
    assert "context too large" in out["error"]


async def test_source_files_truncated_then_changelog_squeezed(make_state, agent_deps, monkeypatch):
    big = "import requests\n" + "x = 1\n" * 2000
    src = source(files={"requirements.txt": MANIFEST, "app/client.py": big}, release_notes="n" * 4000)
    base = await _fixed_tokens(make_state, agent_deps, source())
    monkeypatch.setattr(ca.settings, "LLM_CONTEXT_MAX_TOKENS", base + 300)
    with agent_deps(src):
        out = await assemble_context(make_state())
    p = out["context_payload"]
    assert p["source_files"][0]["truncated"] is True and len(p["source_files"][0]["content"]) < len(big)
    assert p["changelog"] is None  # source files consumed the remaining budget first
    assert p["truncated"] is True and p["source_search_complete"] is False
    assert out["context_token_count"] <= base + 300


async def _fixed_tokens(make_state, agent_deps, src):
    with agent_deps(src):
        out = await assemble_context(make_state())
    p = out["context_payload"]
    return estimate_tokens(__import__("json").dumps(p["cve"])) + estimate_tokens(p["manifest"]["content"])


async def test_files_dropped_when_budget_exhausted_are_not_allowlisted(make_state, agent_deps, monkeypatch):
    big = "import requests\n" + "x = 1\n" * 400
    src = source(
        files={"requirements.txt": MANIFEST, "a.py": big, "b.py": big}, search={"requests": ["a.py", "b.py"]}
    )
    base = await _fixed_tokens(make_state, agent_deps, source())
    monkeypatch.setattr(ca.settings, "LLM_CONTEXT_MAX_TOKENS", base + estimate_tokens(big) + 10)
    with agent_deps(src):
        out = await assemble_context(make_state())
    p = out["context_payload"]
    assert "b.py" in p["omitted_source_paths"] and "b.py" not in p["file_allowlist"]
    assert p["source_search_complete"] is False


async def test_search_failure_is_tolerated_but_marks_incomplete(make_state, agent_deps):
    with agent_deps(source(search_error=RuntimeError("rate limited"))):
        out = await assemble_context(make_state())
    p = out["context_payload"]
    assert "error" not in out and p["source_files"] == [] and p["source_search_complete"] is False


async def test_changelog_failure_is_tolerated(make_state, agent_deps):
    with agent_deps(source(notes_error=RuntimeError("boom"))):
        out = await assemble_context(make_state())
    assert "error" not in out and out["context_payload"]["changelog"] is None


async def test_secrets_are_redacted_before_entering_state(make_state, agent_deps):
    manifest = "--index-url https://u:hunter2hunter2@pypi.corp/simple\nrequests==2.31.0\n"
    leaky = "import requests\nAWS = 'AKIAABCDEFGHIJKLMNOP'\n"
    src = source(files={"requirements.txt": manifest, "app/client.py": leaky})
    with agent_deps(src):
        out = await assemble_context(make_state())
    blob = __import__("json").dumps(out["context_payload"])
    assert "hunter2hunter2" not in blob and "AKIAABCDEFGHIJKLMNOP" not in blob


async def test_ecosystem_import_names_drive_search(make_state, agent_deps):
    src = source(
        files={"requirements.txt": "pyyaml==5.3\n", "c.py": "import yaml\n"}, search={"yaml": ["c.py"]}
    )
    with agent_deps(src):
        out = await assemble_context(make_state(affected_package="PyYAML", target_version="2.32.0"))
    assert [f["path"] for f in out["context_payload"]["source_files"]] == ["c.py"]
    assert ("search_code", ("org/api-gateway", "yaml", "python")) in src.calls
