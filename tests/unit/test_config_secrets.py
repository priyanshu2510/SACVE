import pytest

from src.core.config import Settings, secret_value
from src.core.secrets import (
    AwsSecretsManagerProvider,
    EnvSecretsProvider,
    SecretsError,
    load_secrets,
)


def _settings(monkeypatch, **env: str) -> Settings:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings(_env_file=None)


def test_defaults_are_safe(monkeypatch):
    s = _settings(monkeypatch)
    assert s.MAX_FIX_ATTEMPTS == 3
    assert s.REACHABILITY_MODE == "advisory"
    assert s.SANDBOX_NETWORK_MODE == "none"
    assert s.AUTOMATION_ENABLED is True
    assert s.GITHUB_TOKEN is None


def test_csv_lists_parse(monkeypatch):
    s = _settings(monkeypatch, REPO_BLOCKLIST="legacy-app, archived-service ,", REPO_ALLOWLIST="")
    assert s.REPO_BLOCKLIST == ["legacy-app", "archived-service"]
    assert s.REPO_ALLOWLIST == []


def test_checkpoint_dsn_strips_driver(monkeypatch):
    s = _settings(monkeypatch, DATABASE_URL="postgresql+asyncpg://u:p@h:5432/db")
    assert s.checkpoint_database_url == "postgresql://u:p@h:5432/db"


def test_checkpoint_setup_only_local_by_default(monkeypatch):
    assert _settings(monkeypatch, ENVIRONMENT="local").checkpoint_setup_on_start is True
    assert _settings(monkeypatch, ENVIRONMENT="prod").checkpoint_setup_on_start is False
    s = _settings(monkeypatch, ENVIRONMENT="prod", CHECKPOINT_SETUP_ON_START="true")
    assert s.checkpoint_setup_on_start is True


def test_secret_not_leaked_in_repr(monkeypatch):
    s = _settings(monkeypatch, LLM_API_KEY="super-secret-value")
    assert "super-secret-value" not in repr(s)
    assert secret_value(s.LLM_API_KEY, "LLM_API_KEY") == "super-secret-value"


def test_secret_value_missing_raises(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(SecretsError):
        secret_value(Settings(_env_file=None).GITHUB_TOKEN, "GITHUB_TOKEN")


def test_env_provider(monkeypatch):
    monkeypatch.setenv("FOO_SECRET", "x")
    monkeypatch.setenv("EMPTY_SECRET", "")
    p = EnvSecretsProvider()
    assert p.get("FOO_SECRET") == "x"
    assert p.get("EMPTY_SECRET") is None
    assert p.get("MISSING_SECRET") is None


class _NotFound(Exception):
    pass


class _FakeSM:
    class exceptions:  # noqa: N801 - mirrors boto3 client shape
        ResourceNotFoundException = _NotFound

    def __init__(self, store):
        self.store = store
        self.requested: list[str] = []

    def get_secret_value(self, SecretId):  # noqa: N803
        self.requested.append(SecretId)
        if SecretId not in self.store:
            raise _NotFound()
        return {"SecretString": self.store[SecretId]}


def test_aws_provider_uses_prefix_and_handles_missing():
    client = _FakeSM({"cve/LLM_API_KEY": "k"})
    p = AwsSecretsManagerProvider("us-east-1", "cve/", client=client)
    assert p.get("LLM_API_KEY") == "k"
    assert p.get("GITHUB_TOKEN") is None
    assert client.requested == ["cve/LLM_API_KEY", "cve/GITHUB_TOKEN"]


def test_aws_provider_wraps_other_errors():
    class Boom(_FakeSM):
        def get_secret_value(self, SecretId):  # noqa: N803
            raise RuntimeError("denied")

    p = AwsSecretsManagerProvider("us-east-1", "cve/", client=Boom({}))
    with pytest.raises(SecretsError):
        p.get("X")


def test_load_secrets_skips_missing():
    p = AwsSecretsManagerProvider("r", "p/", client=_FakeSM({"p/A": "1"}))
    assert load_secrets(p, ("A", "B")) == {"A": "1"}


def test_aws_backend_overlays_env(monkeypatch):
    from src.core import config as config_mod

    fake = AwsSecretsManagerProvider("r", "p/", client=_FakeSM({"p/LLM_API_KEY": "from-aws"}))
    monkeypatch.setattr(config_mod, "get_secrets_provider", lambda: fake)
    monkeypatch.setenv("SECRETS_BACKEND", "aws")
    monkeypatch.setenv("LLM_API_KEY", "from-env")
    s = Settings(_env_file=None)
    assert secret_value(s.LLM_API_KEY, "LLM_API_KEY") == "from-aws"
