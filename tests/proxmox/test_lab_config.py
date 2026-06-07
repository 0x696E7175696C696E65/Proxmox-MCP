from __future__ import annotations

from proxmox_mcp.proxmox.lab import LabEnvironmentConfig


def test_lab_config_is_disabled_without_flag() -> None:
    config = LabEnvironmentConfig.from_env({})

    assert config.enabled is False
    assert config.skip_reason == "Set PROXMOX_MCP_LAB_ENABLED=true to run lab tests"


def test_lab_config_reports_missing_required_values() -> None:
    config = LabEnvironmentConfig.from_env({"PROXMOX_MCP_LAB_ENABLED": "true"})

    assert config.enabled is False
    assert config.skip_reason is not None
    assert "PROXMOX_MCP_LAB_API_ENDPOINT" in config.skip_reason


def test_lab_config_reports_missing_credentials() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
        }
    )

    assert config.enabled is False
    assert config.skip_reason is not None
    assert "token or username/password lab credentials" in config.skip_reason


def test_lab_config_builds_read_only_client_settings() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
            "PROXMOX_MCP_LAB_TOKEN_ID": "root@pam!mcp",
            "PROXMOX_MCP_LAB_TOKEN_SECRET": "secret-value",
            "PROXMOX_MCP_LAB_NODE": "pve-a",
            "PROXMOX_MCP_LAB_STORAGE": "local",
            "PROXMOX_MCP_LAB_TLS_VERIFY": "false",
            "PROXMOX_MCP_LAB_ALLOW_INSECURE_TRANSPORT": "true",
        }
    )

    assert config.enabled is True
    assert config.api_endpoint == "https://pve.example.test:8006"
    assert config.token_id == "root@pam!mcp"  # noqa: S105
    assert config.token_secret is not None
    assert config.token_secret.get_secret_value() == "secret-value"
    assert config.node == "pve-a"
    assert config.storage_id == "local"
    assert config.tls_verify is False
    assert config.allow_insecure_transport is True
    assert config.skip_reason is None


def test_lab_config_builds_username_password_client_settings() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
            "PROXMOX_MCP_LAB_USERNAME": "root@pam",
            "PROXMOX_MCP_LAB_PASSWORD": "secret-value",
            "PROXMOX_MCP_LAB_NODE": "pve-a",
            "PROXMOX_MCP_LAB_STORAGE": "local",
        }
    )

    assert config.enabled is True
    assert config.username == "root@pam"
    assert config.password is not None
    assert config.password.get_secret_value() == "secret-value"
    assert config.token_id is None
    assert config.token_secret is None
    assert config.skip_reason is None


def test_lab_config_rejects_plaintext_endpoint_with_token() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "http://pve.example.test:8006",
            "PROXMOX_MCP_LAB_TOKEN_ID": "root@pam!mcp",
            "PROXMOX_MCP_LAB_TOKEN_SECRET": "secret-value",
        }
    )

    assert config.enabled is False
    assert config.skip_reason is not None
    assert "https URL" in config.skip_reason


def test_lab_config_requires_explicit_insecure_tls_opt_in() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
            "PROXMOX_MCP_LAB_TOKEN_ID": "root@pam!mcp",
            "PROXMOX_MCP_LAB_TOKEN_SECRET": "secret-value",
            "PROXMOX_MCP_LAB_TLS_VERIFY": "false",
        }
    )

    assert config.enabled is False
    assert config.skip_reason is not None
    assert "ALLOW_INSECURE_TRANSPORT" in config.skip_reason


def test_lab_config_parses_named_profile() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
            "PROXMOX_MCP_LAB_USERNAME": "root@pam",
            "PROXMOX_MCP_LAB_PASSWORD": "secret-value",
            "PROXMOX_MCP_LAB_NODE": "pve-a",
            "PROXMOX_MCP_LAB_STORAGE": "local",
            "PROXMOX_MCP_LAB_PROFILE": "pve-9-single-node-no-ceph",
        }
    )

    assert config.enabled is True
    assert config.profile == "pve-9-single-node-no-ceph"
    assert config.profile_missing_prerequisites() == ()


def test_lab_config_reports_profile_prerequisites_without_credentials() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
            "PROXMOX_MCP_LAB_USERNAME": "root@pam",
            "PROXMOX_MCP_LAB_PASSWORD": "secret-value",
            "PROXMOX_MCP_LAB_PROFILE": "pve-9-storage-local-local-lvm",
        }
    )

    assert config.enabled is True
    assert config.profile_missing_prerequisites() == (
        "Set PROXMOX_MCP_LAB_NODE for node-scoped storage profile tests",
        "Set PROXMOX_MCP_LAB_STORAGE for local storage profile tests",
    )


def test_lab_config_rejects_unknown_profile() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
            "PROXMOX_MCP_LAB_USERNAME": "root@pam",
            "PROXMOX_MCP_LAB_PASSWORD": "secret-value",
            "PROXMOX_MCP_LAB_PROFILE": "pve-10-unknown",
        }
    )

    assert config.enabled is False
    assert config.skip_reason == "Unknown Proxmox lab profile: pve-10-unknown"
