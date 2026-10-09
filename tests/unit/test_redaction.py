from src.core import redaction
from src.core.redaction import REDACTED, redact_obj, redact_text


def test_redacts_github_and_aws_tokens():
    text = "tok ghp_" + "a" * 36 + " key AKIAABCDEFGHIJKLMNOP end"
    out = redact_text(text, force=True)
    assert "ghp_" not in out and "AKIA" not in out
    assert out.count(REDACTED) == 2


def test_redacts_fine_grained_pat():
    assert REDACTED in redact_text("github_pat_" + "A1b2" * 10, force=True)


def test_redacts_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\ndef\n-----END RSA PRIVATE KEY-----"
    assert redact_text(f"x {pem} y", force=True) == f"x {REDACTED} y"


def test_redacts_key_value_but_keeps_key():
    out = redact_text("DB_PASSWORD=supersecret123 and api_key: 'abcdef123456'", force=True)
    assert "supersecret123" not in out and "abcdef123456" not in out
    assert "DB_PASSWORD=" in out and "api_key" in out


def test_leaves_ordinary_text_alone():
    text = "requests==2.31.0  # bump to 2.32.0 to fix CVE-2024-35195"
    assert redact_text(text, force=True) == text


def test_redact_obj_recurses():
    obj = {"a": ["token=abcdefghij", {"b": "fine"}], "n": 3}
    out = redact_obj(obj, force=True)
    assert out["a"][0] == f"token={REDACTED}"
    assert out["a"][1] == {"b": "fine"} and out["n"] == 3


def test_disabled_flag_is_noop(monkeypatch):
    monkeypatch.setattr(redaction.settings, "REDACT_SECRETS_IN_AUDIT", False)
    assert redact_text("password=hunter2hunter2") == "password=hunter2hunter2"
    monkeypatch.setattr(redaction.settings, "REDACT_SECRETS_IN_AUDIT", True)
    assert REDACTED in redact_text("password=hunter2hunter2")


def test_redacts_url_embedded_credentials():
    out = redact_text("--index-url https://deploy:s3cr3tpass@pypi.internal.co/simple", force=True)
    assert "s3cr3tpass" not in out and "deploy" not in out
    assert "https://" in out and "@pypi.internal.co/simple" in out
