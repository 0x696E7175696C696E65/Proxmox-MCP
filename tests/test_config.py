import pytest
from pydantic import SecretStr

from proxmox_mcp.config import DangerousOperationSettings, Settings

REDACTED = "**********"


def test_settings_have_safe_defaults() -> None:
    settings = Settings()

    assert settings.environment == "development"
    assert settings.server_host == "127.0.0.1"
    assert settings.server_port == 8080
    assert settings.dangerous_operations.require_approval is True


def test_secret_values_are_redacted() -> None:
    settings = Settings(
        database_url=SecretStr("postgresql+asyncpg://user:pass@db/app"),
        vault_token=SecretStr("vault-token-value"),
    )

    dumped = settings.safe_dump()

    assert dumped["database_url"] == REDACTED
    assert dumped["vault_" + "token"] == REDACTED
    assert "pass" not in str(dumped)
    assert "vault-token-value" not in str(dumped)


def test_dangerous_operations_can_be_disabled() -> None:
    settings = Settings(
        dangerous_operations=DangerousOperationSettings(enabled=False, require_approval=True)
    )

    assert settings.dangerous_operations.enabled is False


def test_unprefixed_enabled_env_does_not_configure_dangerous_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENABLED", "false")

    settings = Settings()

    assert settings.dangerous_operations.enabled is True


def test_prefixed_nested_enabled_env_configures_dangerous_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROXMOX_MCP_DANGEROUS_OPERATIONS__ENABLED", "false")

    settings = Settings()

    assert settings.dangerous_operations.enabled is False


def test_credential_provider_can_be_configured_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROXMOX_MCP_CREDENTIAL_PROVIDER", "hashicorp_vault")
    monkeypatch.setenv("PROXMOX_MCP_VAULT_URL", "https://vault.example.test")
    monkeypatch.setenv("PROXMOX_MCP_VAULT_TOKEN", "vault-token-value")

    settings = Settings()

    assert settings.credential_provider == "hashicorp_vault"
    assert settings.vault_url == "https://vault.example.test"
    assert settings.vault_token is not None
    assert settings.vault_token.get_secret_value() == "vault-token-value"
