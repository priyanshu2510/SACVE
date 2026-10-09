import pytest

from src.agent.nodes import reachability as rc
from src.agent.nodes.reachability import analyse_python, assess_reachability, find_python_imports


def ctx(files=None, declares=True, complete=True):
    return {
        "source_files": [{"path": p, "content": c} for p, c in (files or {}).items()],
        "manifest_declares_package": declares,
        "source_search_complete": complete,
    }


@pytest.mark.parametrize(
    "src,expected",
    [
        ("import requests", 1),
        ("import os, requests as r", 1),
        ("from requests import get", 1),
        ("from requests.adapters import HTTPAdapter", 1),
        ("import requests_toolbelt", 0),  # different package, shared prefix
        ("from . import requests", 0),  # relative import
        ("x = 'import requests'", 0),  # string, not an import
    ],
)
def test_find_python_imports(src, expected):
    assert len(find_python_imports(src, ["requests"])) == expected


def test_dotted_import_names():
    assert find_python_imports("from google.protobuf import message", ["google.protobuf"])
    assert not find_python_imports("import google.auth", ["google.protobuf"])


def test_reachable_when_imported():
    ok, ev = analyse_python(ctx({"a.py": "import requests\n"}), ["requests"])
    assert ok and ev["importing_files"]["a.py"][0]["statement"] == "import requests"


def test_unreachable_only_when_everything_is_certain():
    ok, ev = analyse_python(ctx({"a.py": "import os\n"}), ["requests"])
    assert ok is False and "no imports" in ev["reason"]


@pytest.mark.parametrize(
    "context,why",
    [
        (ctx({"a.py": "import os\n"}, declares=False), "transitive"),
        (ctx({"a.py": "import os\n"}, complete=False), "incomplete"),
        (ctx({"a.py": "import importlib\nimportlib.import_module('requests')\n"}), "dynamic"),
        (ctx({"a.py": "def broken(:\n"}), "parsed"),
        (ctx({}, complete=False), "incomplete"),
    ],
)
def test_uncertainty_resolves_to_reachable(context, why):
    ok, ev = analyse_python(context, ["requests"])
    assert ok is True and why in ev["reason"]


def test_non_python_files_ignored():
    ok, _ = analyse_python(ctx({"README.md": "import requests"}), ["requests"])
    assert ok is False


async def test_node_advisory_mode_annotates_only(make_state, monkeypatch):
    monkeypatch.setattr(rc.settings, "REACHABILITY_MODE", "advisory")
    state = make_state(context_payload=ctx({"a.py": "import os\n"}))
    out = await assess_reachability(state)
    assert out["reachable"] is False and "terminal_status" not in out
    assert out["audit_events"][-1]["event_type"] == "REACHABILITY_ASSESSED"
    assert out["audit_events"][-1]["payload"]["mode"] == "advisory"


async def test_node_enforce_mode_terminates(make_state, monkeypatch):
    monkeypatch.setattr(rc.settings, "REACHABILITY_MODE", "enforce")
    out = await assess_reachability(make_state(context_payload=ctx({"a.py": "import os\n"})))
    assert out["terminal_status"] == "NOT_REACHABLE"


async def test_node_enforce_mode_keeps_going_when_reachable(make_state, monkeypatch):
    monkeypatch.setattr(rc.settings, "REACHABILITY_MODE", "enforce")
    out = await assess_reachability(make_state(context_payload=ctx({"a.py": "import requests\n"})))
    assert out["reachable"] is True and "terminal_status" not in out


async def test_other_ecosystems_default_reachable(make_state, monkeypatch):
    monkeypatch.setattr(rc.settings, "REACHABILITY_MODE", "enforce")
    out = await assess_reachability(make_state(ecosystem="npm", context_payload=ctx()))
    assert out["reachable"] is True and out["reachability_evidence"]["method"] == "not_implemented"


async def test_pip_name_aliases_are_used(make_state):
    state = make_state(affected_package="PyYAML", context_payload=ctx({"a.py": "import yaml\n"}))
    assert (await assess_reachability(state))["reachable"] is True
