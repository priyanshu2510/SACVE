"""Secrets loading.

Locally secrets come from the process environment / ``.env`` (handled directly by
Pydantic Settings). In AWS environments ``SECRETS_BACKEND=aws`` makes the settings
layer pull the names in :data:`SECRET_NAMES` from AWS Secrets Manager instead.
Nothing outside ``src/core`` reads credentials directly.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Settings fields that are sourced from the secrets backend.
SECRET_NAMES: tuple[str, ...] = (
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "GITHUB_WEBHOOK_SECRET",
    "LLM_API_KEY",
    "TEAMS_API_KEY",
    "CONFLUENCE_API_TOKEN",
    "JIRA_API_TOKEN",
    "S3_ACCESS_KEY",
    "S3_SECRET_KEY",
    "API_KEY",
    "WEBHOOK_SECRET",
    "SMTP_PASSWORD",
    "PAGERDUTY_ROUTING_KEY",
    "NVD_API_KEY",
)


class SecretsError(RuntimeError):
    """Raised when a required secret cannot be loaded."""


class SecretsProvider(ABC):
    """Source of named secret values."""

    @abstractmethod
    def get(self, name: str) -> str | None:
        """Return the secret value for ``name`` or ``None`` if it does not exist."""


class EnvSecretsProvider(SecretsProvider):
    """Reads secrets from the process environment (populated from ``.env`` locally)."""

    def get(self, name: str) -> str | None:
        """Return ``os.environ[name]`` if set and non-empty."""
        return os.environ.get(name) or None


class AwsSecretsManagerProvider(SecretsProvider):
    """Reads each secret from AWS Secrets Manager as ``{prefix}{NAME}`` (string value)."""

    def __init__(self, region: str, prefix: str, client: Any | None = None) -> None:
        self._prefix = prefix
        if client is None:
            import boto3  # imported lazily so local runs never need AWS config

            client = boto3.client("secretsmanager", region_name=region)
        self._client = client

    def get(self, name: str) -> str | None:
        """Fetch ``{prefix}{name}``; returns ``None`` if the secret does not exist."""
        secret_id = f"{self._prefix}{name}"
        try:
            resp = self._client.get_secret_value(SecretId=secret_id)
        except self._client.exceptions.ResourceNotFoundException:
            return None
        except Exception as exc:
            # Never log the value; log which secret failed.
            log.error("secrets.fetch_failed", secret_id=secret_id, error=str(exc))
            raise SecretsError(f"failed to fetch secret {secret_id}") from exc
        return resp.get("SecretString")


@lru_cache(maxsize=1)
def get_secrets_provider() -> SecretsProvider:
    """Return the provider selected by ``SECRETS_BACKEND`` (``env`` by default)."""
    backend = os.environ.get("SECRETS_BACKEND", "env").lower()
    if backend == "aws":
        return AwsSecretsManagerProvider(
            region=os.environ.get("AWS_REGION", "us-east-1"),
            prefix=os.environ.get("AWS_SECRETS_PREFIX", "cve-remediation/"),
        )
    return EnvSecretsProvider()


def load_secrets(provider: SecretsProvider, names: tuple[str, ...] = SECRET_NAMES) -> dict[str, str]:
    """Load every name in ``names`` from ``provider``, skipping missing ones."""
    out: dict[str, str] = {}
    for name in names:
        value = provider.get(name)
        if value is not None:
            out[name] = value
    return out
