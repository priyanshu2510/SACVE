"""SBOM generation: shallow-clone a repo, run Syft (CycloneDX JSON), store in S3 and PostgreSQL."""

from __future__ import annotations

import asyncio
import json
import os
import posixpath
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol
from urllib.parse import unquote

import boto3
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import Settings, secret_value, settings as default_settings
from src.models.sbom import SBOM
from src.schemas.cve import Ecosystem
from src.services.sandbox.git_clone import clone_repo

log = structlog.get_logger(__name__)

_PURL_ECOSYSTEM = {"pypi": Ecosystem.PIP, "npm": Ecosystem.NPM, "maven": Ecosystem.MAVEN,
                   "golang": Ecosystem.GO, "nuget": Ecosystem.NUGET, "gem": Ecosystem.GEM}  # fmt: skip
# Files a fix can actually edit, best first (a manifest beats the lockfile derived from it).
_MANIFESTS = ("requirements", "constraints", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "package.json", "go.mod",
              "pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "directory.packages.props", "packages.config")  # fmt: skip
_LOCKFILES = ("pipfile.lock", "poetry.lock", "uv.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum",
              "gemfile.lock", "packages.lock.json", "gradle.lockfile")  # fmt: skip
_MANIFEST_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".gemspec")


class SBOMError(RuntimeError):
    """SBOM generation failed."""


@dataclass(frozen=True)
class SBOMComponent:
    """A dependency found in the repository, with the file that declares it."""

    ecosystem: Ecosystem
    name: str
    version: str
    manifest_path: str
    purl: str


def _manifest_rank(path: str) -> int | None:
    """Lower is better; ``None`` if the file is not something a fix can edit."""
    name = posixpath.basename(path).lower()
    if name.endswith(".txt") and name.startswith(_MANIFESTS[:2]):
        return 0
    if name in _MANIFESTS[2:] or name.endswith(_MANIFEST_SUFFIXES):
        return 1
    if name in _LOCKFILES:
        return 2
    return None


def _purl_parts(purl: str) -> tuple[str, str, str] | None:
    """``pkg:type/namespace/name@version?qualifiers`` -> ``(type, full_name, version)``."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    ptype, _, rest = body.partition("/")
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    segments = [unquote(s) for s in path.split("/") if s]
    if not segments or not version:
        return None
    if ptype == "maven" and len(segments) >= 2:
        return ptype, f"{segments[0]}:{segments[-1]}", unquote(version)
    return ptype, "/".join(segments), unquote(version)


def _locations(component: dict[str, Any]) -> list[str]:
    paths = [p["value"] for p in component.get("properties", []) if str(p.get("name", "")).startswith("syft:location:") and str(p["name"]).endswith(":path")]
    for occ in component.get("evidence", {}).get("occurrences", []):
        if occ.get("location"):
            paths.append(occ["location"])
    return [p.lstrip("/") for p in paths]


def parse_cyclonedx(doc: dict[str, Any]) -> list[SBOMComponent]:
    """Extract remediable dependencies: supported ecosystem, exact version, declared in an editable file."""
    found: dict[tuple[Ecosystem, str, str], SBOMComponent] = {}
    for comp in doc.get("components", []):
        if comp.get("type") not in (None, "library", "framework"):
            continue
        parts = _purl_parts(comp.get("purl", ""))
        if parts is None or parts[0] not in _PURL_ECOSYSTEM:
            continue
        ptype, name, version = parts
        if not version[:1].isdigit() and not version.startswith("v"):  # unpinned spec like ">=2.0"
            continue
        ranked = sorted((r, p) for p in _locations(comp) if (r := _manifest_rank(p)) is not None)
        if not ranked:
            continue  # e.g. only seen as installed metadata in site-packages: nothing a PR can change
        eco = _PURL_ECOSYSTEM[ptype]
        found.setdefault((eco, name, version), SBOMComponent(eco, name, version, ranked[0][1], comp["purl"]))
    return sorted(found.values(), key=lambda c: (c.ecosystem.value, c.name.lower(), c.version))


# --------------------------------------------------------------------------- Syft / storage


class SBOMStorage(Protocol):
    """Where SBOM documents are archived (S3 in prod, MinIO locally)."""

    async def put(self, key: str, body: bytes) -> None:
        """Store ``body`` under ``key``."""


class S3SBOMStorage:
    """boto3-backed storage into ``S3_BUCKET_SBOM`` (versioned bucket)."""

    def __init__(self, cfg: Settings | None = None, client: Any | None = None) -> None:
        self._cfg = cfg or default_settings
        self._client = client

    def _s3(self) -> Any:
        if self._client is None:
            self._client = boto3.client(
                "s3",
                endpoint_url=self._cfg.S3_ENDPOINT_URL or None,
                aws_access_key_id=self._cfg.S3_ACCESS_KEY.get_secret_value() if self._cfg.S3_ACCESS_KEY else None,
                aws_secret_access_key=self._cfg.S3_SECRET_KEY.get_secret_value() if self._cfg.S3_SECRET_KEY else None,
                region_name=self._cfg.AWS_REGION,
            )
        return self._client

    async def put(self, key: str, body: bytes) -> None:
        """Upload (blocking boto3 call runs in a worker thread)."""
        await asyncio.to_thread(
            self._s3().put_object, Bucket=self._cfg.S3_BUCKET_SBOM, Key=key, Body=body, ContentType="application/json"
        )


async def run_syft(directory: Path, cfg: Settings | None = None) -> dict[str, Any]:
    """Run ``syft dir:<directory> -o cyclonedx-json`` and return the parsed document."""
    cfg = cfg or default_settings
    try:
        proc = await asyncio.create_subprocess_exec(
            cfg.SYFT_BIN, f"dir:{directory}", "-o", "cyclonedx-json", "-q",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"},
        )  # fmt: skip
    except FileNotFoundError as exc:
        raise SBOMError(f"syft binary {cfg.SYFT_BIN!r} not found (set SYFT_BIN)") from exc
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=cfg.SBOM_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()  # reap the process so no zombie/transport is left behind
        raise SBOMError(f"syft timed out after {cfg.SBOM_TIMEOUT_SECONDS}s") from exc
    if proc.returncode != 0:
        raise SBOMError(f"syft failed (exit {proc.returncode}): {err.decode(errors='replace')[-300:]}")
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise SBOMError(f"syft produced invalid JSON: {exc}") from exc


@dataclass
class GeneratedSBOM:
    """Result of :meth:`SBOMGenerator.generate`."""

    repo_name: str
    commit_sha: str
    document: dict[str, Any]
    s3_key: str
    components: list[SBOMComponent]


class SBOMGenerator:
    """Clone -> Syft -> archive. Collaborators are injectable for tests."""

    def __init__(
        self,
        storage: SBOMStorage | None = None,
        clone: Callable[[str, Path], Awaitable[str]] = clone_repo,
        syft: Callable[[Path], Awaitable[dict[str, Any]]] = run_syft,
    ) -> None:
        self._storage = storage or S3SBOMStorage()
        self._clone, self._syft = clone, syft

    async def generate(self, repo_name: str) -> GeneratedSBOM:
        """Generate and archive the SBOM for the default branch of ``repo_name``."""
        with tempfile.TemporaryDirectory(prefix="cve-sbom-") as tmp:
            dest = Path(tmp) / "repo"
            sha = await self._clone(repo_name, dest)
            document = await self._syft(dest)
        key = f"{repo_name}/{sha}.cdx.json"
        await self._storage.put(key, json.dumps(document).encode())
        components = parse_cyclonedx(document)
        log.info("sbom.generated", repo=repo_name, commit=sha, components=len(components))
        return GeneratedSBOM(repo_name, sha, document, key, components)


async def save_sbom(session: AsyncSession, repo_id: Any, generated: GeneratedSBOM) -> SBOM:
    """Persist the SBOM row (history is kept; the newest row per repo is the current one)."""
    row = SBOM(repo_id=repo_id, commit_sha=generated.commit_sha, document=generated.document, s3_key=generated.s3_key)
    session.add(row)
    await session.flush()
    return row
