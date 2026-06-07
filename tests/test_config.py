from collections.abc import Mapping
from typing import cast

import pytest
from pydantic import SecretStr

from proxmox_mcp.config import (
    DangerousOperationSettings,
    ObservabilitySettings,
    Settings,
    TlsSettings,
)

REDACTED = "**********"


def test_settings_have_safe_defaults() -> None:
    settings = Settings()

    assert settings.environment == "development"
    assert settings.server_host == "127.0.0.1"
    assert settings.server_port == 8443
    assert "ssl=require" in settings.database_url.get_secret_value()
    assert settings.redis_url.get_secret_value().startswith("rediss://")
    assert settings.tls.generate_self_signed is True
    assert settings.tls.cert_file is None
    assert settings.tls.key_file is None
    assert settings.dangerous_operations.require_approval is True


def test_secret_values_are_redacted() -> None:
    settings = Settings(
        database_url=SecretStr("postgresql+asyncpg://user:pass@db/app?ssl=require"),
        vault_token=SecretStr("vault-token-value"),
    )

    dumped = settings.safe_dump()

    assert dumped["database_url"] == REDACTED
    assert dumped["vault_" + "token"] == REDACTED
    assert "user:pass@db" not in str(dumped)
    assert "vault-token-value" not in str(dumped)


def test_tls_key_path_is_redacted_from_safe_dump() -> None:
    settings = Settings(
        tls=TlsSettings(
            cert_file="C:/certs/server.crt",
            key_file=SecretStr("C:/certs/server.key"),
            generate_self_signed=False,
        )
    )

    dumped = settings.safe_dump()
    tls_dump = cast(Mapping[str, object], dumped["tls"])

    assert tls_dump["cert_file"] == "C:/certs/server.crt"
    assert tls_dump["key_file"] == REDACTED
    assert "server.key" not in str(dumped)


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


def test_enterprise_credential_providers_can_be_configured_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROXMOX_MCP_CREDENTIAL_PROVIDER", "azure_key_vault")
    monkeypatch.setenv("PROXMOX_MCP_AZURE_KEY_VAULT_URL", "https://vault.example.test")

    settings = Settings()

    assert settings.credential_provider == "azure_key_vault"
    assert settings.azure_key_vault_url == "https://vault.example.test"


def test_external_secret_provider_urls_require_https() -> None:
    with pytest.raises(ValueError, match="Vault URL"):
        Settings(
            credential_provider="hashicorp_vault",
            vault_url="http://vault.example.test",
            vault_token=SecretStr("vault-token"),
        )

    with pytest.raises(ValueError, match="Azure Key Vault URL"):
        Settings(
            credential_provider="azure_key_vault",
            azure_key_vault_url="http://vault.example.test",
        )


def test_tls_settings_can_be_configured_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROXMOX_MCP_TLS__CERT_FILE", "C:/certs/tls.crt")
    monkeypatch.setenv("PROXMOX_MCP_TLS__KEY_FILE", "C:/certs/tls.key")
    monkeypatch.setenv("PROXMOX_MCP_TLS__GENERATE_SELF_SIGNED", "false")
    monkeypatch.setenv("PROXMOX_MCP_TLS__COMMON_NAME", "mcp.example.test")
    monkeypatch.setenv("PROXMOX_MCP_TLS__SUBJECT_ALT_NAMES", '["mcp.example.test","127.0.0.1"]')

    settings = Settings()

    assert settings.tls.cert_file == "C:/certs/tls.crt"
    assert settings.tls.key_file is not None
    assert settings.tls.key_file.get_secret_value() == "C:/certs/tls.key"
    assert settings.tls.generate_self_signed is False
    assert settings.tls.common_name == "mcp.example.test"
    assert settings.tls.subject_alt_names == ("mcp.example.test", "127.0.0.1")


def test_database_url_requires_tls() -> None:
    with pytest.raises(ValueError, match="PostgreSQL TLS"):
        Settings(database_url=SecretStr("postgresql+asyncpg://user:pass@db/app"))


def test_redis_url_requires_tls() -> None:
    with pytest.raises(ValueError, match="Redis TLS"):
        Settings(redis_url=SecretStr("redis://redis.example:6379/5"))


def test_external_observability_urls_require_https() -> None:
    with pytest.raises(ValueError, match="External observability URLs"):
        Settings(
            observability=ObservabilitySettings(
                alertmanager_url="http://alerts.example",
                prometheus_url="https://prometheus.example",
            )
        )

    with pytest.raises(ValueError, match="External observability URLs"):
        Settings(
            observability=ObservabilitySettings(
                alertmanager_url="https://alerts.example",
                prometheus_url="http://prometheus.example",
            )
        )
