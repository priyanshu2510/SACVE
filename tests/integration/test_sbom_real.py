"""Real Syft and real S3 (MinIO)."""

import json
import shutil
import subprocess
import uuid
from pathlib import Path

import boto3
import pytest

from src.core.config import Settings, settings
from src.schemas.cve import Ecosystem
from src.services.sbom.generator import S3SBOMStorage, SBOMGenerator, parse_cyclonedx, run_syft


def _syft_available() -> bool:
    return shutil.which(settings.SYFT_BIN) is not None or Path(settings.SYFT_BIN).exists()


@pytest.fixture
def repo_dir(tmp_path) -> Path:
    root = tmp_path / "origin"
    (root / "svc").mkdir(parents=True)
    (root / "svc" / "requirements.txt").write_text("requests==2.31.0\nflask>=2.0\nPyYAML==5.3.1\n")
    (root / "go.mod").write_text("module example.com/x\n\ngo 1.21\n\nrequire github.com/opencontainers/runc v1.1.5\n")
    return root


@pytest.mark.syft
async def test_real_syft_output_is_parsed(repo_dir):
    if not _syft_available():
        pytest.skip("syft binary not available (set SYFT_BIN)")
    comps = {c.name: c for c in parse_cyclonedx(await run_syft(repo_dir))}
    assert comps["requests"].version == "2.31.0" and comps["requests"].manifest_path == "svc/requirements.txt"
    assert comps["pyyaml"].ecosystem == Ecosystem.PIP and "flask" not in comps
    assert comps["github.com/opencontainers/runc"].version == "v1.1.5" and comps["github.com/opencontainers/runc"].manifest_path == "go.mod"


def _s3():
    client = boto3.client("s3", endpoint_url=settings.S3_ENDPOINT_URL,
                          aws_access_key_id=settings.S3_ACCESS_KEY.get_secret_value() if settings.S3_ACCESS_KEY else "x",
                          aws_secret_access_key=settings.S3_SECRET_KEY.get_secret_value() if settings.S3_SECRET_KEY else "x",
                          region_name=settings.AWS_REGION)  # fmt: skip
    try:
        client.head_bucket(Bucket=settings.S3_BUCKET_SBOM)
    except Exception:
        pytest.skip("local S3 (MinIO) / bucket not available - run scripts/init_local_storage.py")
    return client


@pytest.mark.s3
async def test_sbom_archived_to_s3_with_versioning():
    s3 = _s3()
    key = f"it/{uuid.uuid4().hex}.cdx.json"
    storage = S3SBOMStorage(Settings())
    await storage.put(key, b'{"v": 1}')
    await storage.put(key, b'{"v": 2}')
    assert json.loads(s3.get_object(Bucket=settings.S3_BUCKET_SBOM, Key=key)["Body"].read()) == {"v": 2}
    versions = s3.list_object_versions(Bucket=settings.S3_BUCKET_SBOM, Prefix=key)["Versions"]
    assert len(versions) == 2  # the bucket is versioned: nothing is ever overwritten
    for v in versions:
        s3.delete_object(Bucket=settings.S3_BUCKET_SBOM, Key=key, VersionId=v["VersionId"])


@pytest.mark.s3
@pytest.mark.syft
async def test_generator_end_to_end_with_real_syft_and_s3(repo_dir):
    if not _syft_available():
        pytest.skip("syft binary not available")
    s3 = _s3()

    async def clone(repo_name, dest: Path) -> str:
        shutil.copytree(repo_dir, dest)
        subprocess.run(["git", "-C", str(dest), "init", "-q"], check=True)
        return "deadbeef"

    repo = f"it-{uuid.uuid4().hex[:8]}/api"
    result = await SBOMGenerator(S3SBOMStorage(Settings()), clone=clone).generate(repo)
    assert {c.name for c in result.components} >= {"requests", "pyyaml", "github.com/opencontainers/runc"}
    body = json.loads(s3.get_object(Bucket=settings.S3_BUCKET_SBOM, Key=result.s3_key)["Body"].read())
    assert body["bomFormat"] == "CycloneDX" and result.s3_key == f"{repo}/deadbeef.cdx.json"
    for v in s3.list_object_versions(Bucket=settings.S3_BUCKET_SBOM, Prefix=result.s3_key)["Versions"]:
        s3.delete_object(Bucket=settings.S3_BUCKET_SBOM, Key=result.s3_key, VersionId=v["VersionId"])
