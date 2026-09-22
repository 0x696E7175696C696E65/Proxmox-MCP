from __future__ import annotations

from pydantic import SecretStr

from proxmox_mcp.config import Settings
from proxmox_mcp.security.redaction import REDACTED_VALUE, sanitize_for_security_boundary


def test_redaction_covers_extended_sensitive_keys() -> None:
    payload = {
        "authorization": "Bearer secret",
        "cookie": "session=abc",
        "csrf_token": "csrf",
        "ticket": "PVE:ticket",
        "nested": {"set_cookie": "x", "ok": 1},
    }
    sanitized = sanitize_for_security_boundary(payload)
    assert isinstance(sanitized, dict)
    assert sanitized["authorization"] == REDACTED_VALUE
    assert sanitized["cookie"] == REDACTED_VALUE
    assert sanitized["csrf_token"] == REDACTED_VALUE
    assert sanitized["ticket"] == REDACTED_VALUE
    nested = sanitized["nested"]
    assert isinstance(nested, dict)
    assert nested["set_cookie"] == REDACTED_VALUE
    assert nested["ok"] == 1


def test_settings_safe_dump_redacts_secrets() -> None:
    settings = Settings(
        environment="test",
        service_token=SecretStr("super-secret-token-value"),
        auth_mode="service_token",
    )
    dumped = settings.safe_dump()
    blob = str(dumped)
    assert "super-secret-token-value" not in blob
    assert dumped.get("service_token") == REDACTED_VALUE


def test_production_rejects_development_auth_mode() -> None:
    import pytest

    with pytest.raises(ValueError, match="development auth mode"):
        Settings(environment="production", auth_mode="development")
