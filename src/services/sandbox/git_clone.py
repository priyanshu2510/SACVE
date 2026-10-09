"""Host-side repository cloning (the sandbox itself has no network and never sees the token)."""

from __future__ import annotations

import asyncio
import base64
import os
from pathlib import Path
from urllib.parse import urlparse

import structlog

from src.core.config import Settings, secret_value, settings as default_settings
from src.services.sandbox.base import SandboxError

log = structlog.get_logger(__name__)


def web_base_url(api_url: str) -> str:
    """``https://api.github.com`` -> ``https://github.com``; GHE ``https://h/api/v3`` -> ``https://h``."""
    parsed = urlparse(api_url)
    host = parsed.netloc
    if host == "api.github.com":
        host = "github.com"
    return f"{parsed.scheme}://{host}"


async def clone_repo(repo_name: str, dest: Path, cfg: Settings | None = None) -> str:
    """Shallow-clone ``repo_name`` (``owner/name``) into ``dest`` and return the checked-out commit SHA.

    The token is passed through git's environment-based config (not argv, not ``.git/config``).
    """
    cfg = cfg or default_settings
    token = secret_value(cfg.GITHUB_TOKEN, "GITHUB_TOKEN")
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }
    url = f"{web_base_url(cfg.GITHUB_API_URL)}/{repo_name}.git"
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", "--quiet", url, str(dest),
        env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )  # fmt: skip
    out, _ = await proc.communicate()
    if proc.returncode != 0:
        message = out.decode(errors="replace").replace(token, "[REDACTED]").replace(basic, "[REDACTED]")
        raise SandboxError(f"git clone of {repo_name} failed: {message.strip()[:500]}")
    rev = await asyncio.create_subprocess_exec(
        "git", "-C", str(dest), "rev-parse", "HEAD", stdout=asyncio.subprocess.PIPE
    )
    sha, _ = await rev.communicate()
    return sha.decode().strip()
