"""Typed application configuration (Pydantic Settings). All env vars are declared here."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from src.core.secrets import SECRET_NAMES, SecretsError, get_secrets_provider, load_secrets


class _SecretsManagerSource(PydanticBaseSettingsSource):
    """Settings source that overlays AWS Secrets Manager values when ``SECRETS_BACKEND=aws``."""

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:  # pragma: no cover
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        if os.environ.get("SECRETS_BACKEND", "env").lower() != "aws":
            return {}
        return dict(load_secrets(get_secrets_provider(), SECRET_NAMES))


class Settings(BaseSettings):
    """All runtime configuration. Credentials are ``SecretStr`` and never logged."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # Runtime
    ENVIRONMENT: Literal["local", "dev", "staging", "prod"] = "local"
    SECRETS_BACKEND: Literal["env", "aws"] = "env"
    AWS_REGION: str = "us-east-1"
    AWS_SECRETS_PREFIX: str = "cve-remediation/"
    CHECKPOINT_SETUP_ON_START: bool | None = None

    # Database / queue
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/cve_remediation"
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # GitHub
    GITHUB_TOKEN: SecretStr | None = None
    GITHUB_WEBHOOK_SECRET: SecretStr | None = None
    GITHUB_ORG: str = "your-org-name"
    GITHUB_API_URL: str = "https://api.github.com"
    GITHUB_SECONDS_BETWEEN_REQUESTS: float = 0.25  # PyGithub's pacing against secondary rate limits (GitHub advises >= 1s between writes)
    GITHUB_SECONDS_BETWEEN_WRITES: float = 1.0

    # Internal LLM
    LLM_API_BASE_URL: str = "https://internal-llm.company.com"
    LLM_API_KEY: SecretStr | None = None
    LLM_MODEL_NAME: str = "your-model-name"
    LLM_MAX_TOKENS: int = 4096
    LLM_TIMEOUT_SECONDS: int = 120
    LLM_CONTEXT_MAX_TOKENS: int = 8000

    # Teams / Confluence / JIRA
    TEAMS_API_ENDPOINT: str = "https://internal-teams.company.com/api/notify"
    TEAMS_API_KEY: SecretStr | None = None
    CONFLUENCE_BASE_URL: str = "https://company.atlassian.net"
    CONFLUENCE_SPACE_KEY: str = "SEC"
    CONFLUENCE_PARENT_PAGE_ID: str = "123456"
    CONFLUENCE_USER: str = "automation@company.com"
    CONFLUENCE_API_TOKEN: SecretStr | None = None
    JIRA_BASE_URL: str = "https://company.atlassian.net"
    JIRA_PROJECT_KEY: str = "SEC"
    JIRA_USER: str = "automation@company.com"
    JIRA_API_TOKEN: SecretStr | None = None

    # Object storage
    S3_ENDPOINT_URL: str | None = "http://localhost:9000"
    S3_ACCESS_KEY: SecretStr | None = None
    S3_SECRET_KEY: SecretStr | None = None
    S3_BUCKET_SBOM: str = "cve-sboms"
    S3_BUCKET_LOGS: str = "cve-job-logs"

    # CVE feeds
    NVD_API_KEY: SecretStr | None = None
    NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    OSV_API_BASE_URL: str = "https://api.osv.dev"
    CVE_HTTP_TIMEOUT_SECONDS: int = 30

    # Control API
    API_KEY: SecretStr | None = None
    CONTROL_API_IP_ALLOWLIST: Annotated[list[str], NoDecode] = []
    CONTROL_API_URL: str = "http://localhost:8000"

    # Thresholds
    MIN_CVSS_THRESHOLD: float = 4.0
    SANDBOX_TIMEOUT_SECONDS: int = 600

    # Repo selection
    REPO_ALLOWLIST: Annotated[list[str], NoDecode] = []
    REPO_BLOCKLIST: Annotated[list[str], NoDecode] = []

    # Notifications
    ENABLED_NOTIFICATION_CHANNELS: Annotated[list[str], NoDecode] = ["teams", "webhook"]
    WEBHOOK_URL: str | None = None
    WEBHOOK_SECRET: SecretStr | None = None
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USER: str | None = None
    SMTP_PASSWORD: SecretStr | None = None
    EMAIL_FROM: str | None = None
    PAGERDUTY_ROUTING_KEY: SecretStr | None = None

    # Pipeline
    MAX_NEW_JOBS_PER_RUN: int = 50  # cap on jobs created per matcher run (protects LLM spend after a big SBOM/CVE batch)
    FAILED_JOB_RETRY_AFTER_HOURS: int = 24
    SLA_ESCALATION_AFTER_HOURS: int = 24
    SYFT_BIN: str = "syft"
    SBOM_TIMEOUT_SECONDS: int = 300
    REPO_LOCK_TTL_SECONDS: int = 10_800

    # Tracking (JIRA / Confluence)
    JIRA_ISSUE_TYPE: str = "Task"
    JIRA_SEVERITIES: Annotated[list[str], NoDecode] = ["CRITICAL", "HIGH"]  # severities that get a ticket
    JIRA_STATUS_TRANSITIONS: dict[str, str] = {"PR_RAISED": "In Review", "MERGED": "Done", "BLOCKED": "Blocked"}  # job status -> JIRA status

    # Pull requests / notifications
    PR_BRANCH_PREFIX: str = "fix/cve-"
    PR_LABELS: Annotated[list[str], NoDecode] = ["security", "cve-fix", "automated"]
    OWNER_EMAIL_DOMAIN: str | None = None  # maps GitHub @user -> user@domain for notification recipients

    # v1 locked additions
    MAX_FIX_ATTEMPTS: int = 3
    REACHABILITY_MODE: Literal["enforce", "advisory"] = "advisory"
    SANDBOX_NETWORK_MODE: Literal["none", "registry-allowlist"] = "none"
    MAX_CONCURRENT_SANDBOXES: int = 10
    SANDBOX_SLOT_LEASE_SECONDS: int = 21_600  # a crashed worker's slot frees itself after this
    SANDBOX_SLOTS_BACKEND: Literal["local", "redis"] = "local"  # redis = cap shared by all workers (use in dev/staging/prod)
    SANDBOX_IMAGE_PYTHON: str = "cve-sandbox-python:latest"  # python:3.12-slim + git + grype (docker/sandbox/)
    SANDBOX_EGRESS_NETWORK: str = "cve-sandbox-egress"  # attached only for installs in registry-allowlist mode
    SANDBOX_ALLOW_NON_INTERNAL_NETWORK: bool = False  # local dev only: lets the egress network be a plain bridge
    SANDBOX_PROXY_URL: str | None = None  # allowlisting proxy that fronts the package registry
    SANDBOX_PIP_INDEX_URL: str | None = None  # internal package registry for pip
    SANDBOX_MEM_LIMIT: str = "2g"
    SANDBOX_CPU_QUOTA: int = 50000
    SANDBOX_PIDS_LIMIT: int = 256
    SANDBOX_WORKSPACE_TMPFS: str = "512m"
    SANDBOX_VENV_TMPFS: str = "768m"
    REQUIRE_TESTS: bool = True  # a repo with no tests cannot be validated, so no PR is raised
    AUTOMATION_ENABLED: bool = True
    SUPPLY_CHAIN_VERIFY: bool = True
    CONTEXT_FILE_ALLOWLIST_ENFORCED: bool = True
    REDACT_SECRETS_IN_AUDIT: bool = True
    CLOUDWATCH_NAMESPACE: str = "CVEAutoRemediation"
    XRAY_ENABLED: bool = True

    @field_validator(
        "CONTROL_API_IP_ALLOWLIST",
        "REPO_ALLOWLIST",
        "REPO_BLOCKLIST",
        "ENABLED_NOTIFICATION_CHANNELS",
        "PR_LABELS",
        "JIRA_SEVERITIES",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, value: Any) -> Any:
        """Accept comma-separated strings for list-valued env vars."""
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Priority: init > AWS Secrets Manager (when enabled) > env > .env."""
        return (
            init_settings,
            _SecretsManagerSource(settings_cls),
            env_settings,
            dotenv_settings,
            file_secret_settings,
        )

    @property
    def checkpoint_database_url(self) -> str:
        """Plain ``postgresql://`` DSN for psycopg (LangGraph's checkpointer rejects driver suffixes)."""
        url = self.DATABASE_URL
        for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://", "postgresql+psycopg2://"):
            if url.startswith(prefix):
                return "postgresql://" + url[len(prefix) :]
        return url

    @property
    def checkpoint_setup_on_start(self) -> bool:
        """Auto-create checkpoint tables only in local dev unless explicitly overridden."""
        if self.CHECKPOINT_SETUP_ON_START is not None:
            return self.CHECKPOINT_SETUP_ON_START
        return self.ENVIRONMENT == "local"


def secret_value(secret: SecretStr | None, name: str) -> str:
    """Return a secret's plaintext, raising :class:`SecretsError` if it is not configured."""
    if secret is None or not secret.get_secret_value():
        raise SecretsError(f"required secret {name} is not configured")
    return secret.get_secret_value()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide cached :class:`Settings`."""
    return Settings()


settings: Settings = get_settings()
