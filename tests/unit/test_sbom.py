import json
from pathlib import Path

import pytest

from src.schemas.cve import Ecosystem
from src.services.sbom import generator as gen
from src.services.sbom.generator import S3SBOMStorage, SBOMError, SBOMGenerator, _manifest_rank, _purl_parts, parse_cyclonedx
from src.core.config import Settings

FIX = Path(__file__).resolve().parents[1] / "fixtures"
SAMPLE = json.loads((FIX / "syft_sample.cdx.json").read_text())  # real Syft output


def by_name(components):
    return {c.name: c for c in components}


def test_parses_real_syft_output():
    comps = by_name(parse_cyclonedx(SAMPLE))
    assert comps["requests"].ecosystem == Ecosystem.PIP and comps["requests"].version == "2.31.0"
    assert comps["requests"].manifest_path == "svc/requirements.txt"  # leading slash stripped
    assert comps["pyyaml"].version == "5.3.1"
    assert comps["github.com/opencontainers/runc"].ecosystem == Ecosystem.GO
    assert comps["github.com/opencontainers/runc"].version == "v1.1.5" and comps["github.com/opencontainers/runc"].manifest_path == "api/go.mod"
    assert comps["lodash"].ecosystem == Ecosystem.NPM and comps["lodash"].manifest_path == "web/package-lock.json"
    assert comps["org.apache.logging.log4j:log4j-core"].ecosystem == Ecosystem.MAVEN  # group:artifact
    assert comps["org.apache.logging.log4j:log4j-core"].manifest_path == "java/pom.xml"


def test_unpinned_requirements_are_not_components():
    assert "flask" not in by_name(parse_cyclonedx(SAMPLE))  # 'flask>=2.0' has no exact version to match


def test_non_library_and_foreign_components_ignored():
    doc = {"components": [
        {"type": "file", "name": "x"},
        {"type": "library", "purl": "pkg:cargo/serde@1.0.0", "properties": [{"name": "syft:location:0:path", "value": "/Cargo.toml"}]},
        {"type": "library", "purl": "pkg:pypi/foo@1.0", "properties": [{"name": "syft:location:0:path", "value": "/venv/lib/foo-1.0.dist-info/METADATA"}]},
        {"type": "library", "purl": "garbage"},
    ]}  # fmt: skip
    assert parse_cyclonedx(doc) == []


def test_prefers_manifest_over_lockfile_and_dedups():
    doc = {"components": [
        {"type": "library", "purl": "pkg:pypi/requests@2.31.0", "properties": [
            {"name": "syft:location:0:path", "value": "/poetry.lock"}, {"name": "syft:location:1:path", "value": "/pyproject.toml"}]},
        {"type": "library", "purl": "pkg:pypi/requests@2.31.0", "properties": [{"name": "syft:location:0:path", "value": "/requirements.txt"}]},
    ]}  # fmt: skip
    (c,) = parse_cyclonedx(doc)
    assert c.manifest_path == "pyproject.toml"


def test_evidence_occurrences_are_understood():
    doc = {"components": [{"type": "library", "purl": "pkg:pypi/a@1.0", "evidence": {"occurrences": [{"location": "/sub/requirements-dev.txt"}]}}]}
    assert parse_cyclonedx(doc)[0].manifest_path == "sub/requirements-dev.txt"


@pytest.mark.parametrize(
    "path,rank",
    [("requirements.txt", 0), ("a/requirements-dev.txt", 0), ("constraints.txt", 0), ("pyproject.toml", 1), ("go.mod", 1), ("App.csproj", 1),
     ("package-lock.json", 2), ("go.sum", 2), ("README.md", None), ("src/app.py", None)],
)  # fmt: skip
def test_manifest_rank(path, rank):
    assert _manifest_rank(path) == rank


@pytest.mark.parametrize(
    "purl,expected",
    [("pkg:pypi/requests@2.31.0", ("pypi", "requests", "2.31.0")), ("pkg:npm/%40babel/core@7.0.0", ("npm", "@babel/core", "7.0.0")),
     ("pkg:maven/org.x/y@1.0?type=jar", ("maven", "org.x:y", "1.0")), ("pkg:golang/github.com/a/b@v1.2.3", ("golang", "github.com/a/b", "v1.2.3")),
     ("pkg:pypi/noversion", None), ("notapurl", None)],
)  # fmt: skip
def test_purl_parts(purl, expected):
    assert _purl_parts(purl) == expected


# ------------------------------------------------------------------ generator & storage
class MemStorage:
    def __init__(self):
        self.objects = {}

    async def put(self, key, body):
        self.objects[key] = body


async def test_generate_clones_runs_syft_archives_and_parses(tmp_path):
    cloned = []

    async def clone(repo, dest: Path):
        dest.mkdir(parents=True)
        cloned.append((repo, dest))
        return "abc123"

    seen = []

    async def syft(directory: Path):
        seen.append(directory)
        return SAMPLE

    storage = MemStorage()
    result = await SBOMGenerator(storage, clone, syft).generate("org/api")
    assert cloned[0][0] == "org/api" and seen == [cloned[0][1]] and not cloned[0][1].exists()  # temp clone removed
    assert result.s3_key == "org/api/abc123.cdx.json" and json.loads(storage.objects[result.s3_key])["bomFormat"] == "CycloneDX"
    assert result.commit_sha == "abc123" and len(result.components) == 7


async def test_generate_propagates_failures_without_archiving():
    async def clone(repo, dest):
        dest.mkdir(parents=True)
        return "sha"

    async def syft(directory):
        raise SBOMError("syft exploded")

    storage = MemStorage()
    with pytest.raises(SBOMError):
        await SBOMGenerator(storage, clone, syft).generate("org/api")
    assert storage.objects == {}


async def test_run_syft_missing_binary_is_a_clear_error(tmp_path):
    with pytest.raises(SBOMError, match="not found"):
        await gen.run_syft(tmp_path, Settings(_env_file=None, SYFT_BIN="/nonexistent/syft"))


async def test_run_syft_failure_and_bad_output(tmp_path):
    script = tmp_path / "fake-syft"
    script.write_text("#!/bin/sh\necho 'boom' >&2\nexit 3\n")
    script.chmod(0o755)
    with pytest.raises(SBOMError, match="exit 3"):
        await gen.run_syft(tmp_path, Settings(_env_file=None, SYFT_BIN=str(script)))
    script.write_text("#!/bin/sh\necho 'not json'\n")
    with pytest.raises(SBOMError, match="invalid JSON"):
        await gen.run_syft(tmp_path, Settings(_env_file=None, SYFT_BIN=str(script)))


async def test_run_syft_timeout(tmp_path):
    script = tmp_path / "slow-syft"
    script.write_text("#!/bin/sh\nexec sleep 30\n")
    script.chmod(0o755)
    with pytest.raises(SBOMError, match="timed out"):
        await gen.run_syft(tmp_path, Settings(_env_file=None, SYFT_BIN=str(script), SBOM_TIMEOUT_SECONDS=1))


async def test_s3_storage_uses_configured_bucket():
    calls = []

    class Client:
        def put_object(self, **kw):
            calls.append(kw)

    await S3SBOMStorage(Settings(_env_file=None, S3_BUCKET_SBOM="my-boms"), Client()).put("a/b.json", b"{}")
    assert calls == [{"Bucket": "my-boms", "Key": "a/b.json", "Body": b"{}", "ContentType": "application/json"}]
