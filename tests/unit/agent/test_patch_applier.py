from src.agent.deps import override_deps
from src.agent.nodes.patch_applier import apply_patch
from src.agent.state import FileChange
from tests.fakes import FakeSandboxManager

REQS = "flask==3.0.0\nrequests==2.31.0\n"


def change(path="requirements.txt", orig="requests==2.31.0", new="requests==2.32.0"):
    return FileChange(file_path=path, original_content=orig, new_content=new, change_description="bump")


async def setup(make_state, files, changes):
    mgr = FakeSandboxManager(files)
    sb = await mgr.create(job_id="j", repo_name="o/r", ecosystem="pip")
    return mgr, sb, make_state(sandbox_container_id=sb.container_id, file_changes=changes, fix_attempt=1)


async def test_applies_change_after_resetting(make_state):
    mgr, sb, state = await setup(make_state, {"requirements.txt": REQS}, [change()])
    sb.files["requirements.txt"] = "dirty leftovers from a previous attempt"
    with override_deps(sandbox_manager=mgr):
        out = await apply_patch(state)
    assert sb.resets == 1 and sb.files["requirements.txt"] == "flask==3.0.0\nrequests==2.32.0\n"
    assert out["audit_events"][-1]["event_type"] == "PATCH_APPLIED" and "failure_reason" not in out


async def test_multiple_changes_to_one_file_accumulate(make_state):
    changes = [change(), change(orig="flask==3.0.0", new="flask==3.0.3")]
    mgr, sb, state = await setup(make_state, {"requirements.txt": REQS}, changes)
    with override_deps(sandbox_manager=mgr):
        await apply_patch(state)
    assert sb.files["requirements.txt"] == "flask==3.0.3\nrequests==2.32.0\n"


async def test_missing_section_is_repairable(make_state):
    mgr, sb, state = await setup(make_state, {"requirements.txt": "requests==2.30.0\n"}, [change()])
    with override_deps(sandbox_manager=mgr):
        out = await apply_patch(state)
    assert "was not found" in out["failure_reason"] and out["previous_attempts"][0]["fix_attempt"] == 1
    assert sb.files["requirements.txt"] == "requests==2.30.0\n"  # nothing written


async def test_ambiguous_section_is_repairable(make_state):
    mgr, sb, state = await setup(make_state, {"requirements.txt": "requests==2.31.0\nrequests==2.31.0\n"}, [change()])
    with override_deps(sandbox_manager=mgr):
        out = await apply_patch(state)
    assert "matches 2 places" in out["failure_reason"]


async def test_missing_file_is_repairable_and_partial_writes_do_not_happen(make_state):
    changes = [change(), change(path="nope.txt")]
    mgr, sb, state = await setup(make_state, {"requirements.txt": REQS}, changes)
    with override_deps(sandbox_manager=mgr):
        out = await apply_patch(state)
    assert "nope.txt does not exist" in out["failure_reason"]
    assert sb.files["requirements.txt"] == REQS  # first change was not written either


async def test_requires_sandbox_and_changes(make_state):
    assert "requires a sandbox" in (await apply_patch(make_state()))["error"]
