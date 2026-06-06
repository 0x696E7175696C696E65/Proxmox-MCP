import pytest
from pydantic import SecretStr

from proxmox_mcp.config import DangerousOperationSettings, Settings


def test_settings_have_safe_defaults() -> None:
    settings = Settings()

    assert settings.environment == "development"
    assert settings.server_host == "127.0.0.1"
    assert settings.server_port == 8080
    assert settings.dangerous_operations.require_approval is True


def test_secret_values_are_redacted() -> None:
    settings = Settings(database_url=SecretStr("postgresql+asyncpg://user:pass@db/app"))

    dumped = settings.safe_dump()

    assert dumped["database_url"] == "**********"
    assert "pass" not in str(dumped)


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
