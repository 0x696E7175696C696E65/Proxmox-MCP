from __future__ import annotations

import pytest
from pydantic import SecretStr

from proxmox_mcp.config import Settings, TlsSettings
from proxmox_mcp.proxmox import ProxmoxClusterConfig
from proxmox_mcp.secrets import CredentialRef
from proxmox_mcp.server.tls import TlsConfigurationError, resolve_tls_config


def make_credential_ref() -> CredentialRef:
    return CredentialRef(
        provider="development",
        path="secret/proxmox/lab/api-token",
        purpose="proxmox_api",
    )


def test_proxmox_cluster_endpoint_requires_https_in_all_environments() -> None:
    with pytest.raises(ValueError, match="https"):
        ProxmoxClusterConfig(
            cluster_id="lab-pve",
            name="Lab PVE",
            api_endpoint="http://pve.example.test:8006/api2/json",
            credential_ref=make_credential_ref(),
            environment="development",
        )


def test_production_cluster_still_requires_tls_verification() -> None:
    with pytest.raises(ValueError, match="TLS"):
        ProxmoxClusterConfig(
            cluster_id="prod-pve",
            name="Production PVE",
            api_endpoint="https://pve.example.test:8006/api2/json",
            tls_verify=False,
            credential_ref=make_credential_ref(),
            environment="production",
        )


def test_database_and_redis_urls_fail_closed_without_tls() -> None:
    with pytest.raises(ValueError, match="PostgreSQL TLS"):
        Settings(database_url=SecretStr("postgresql+asyncpg://user:pass@db/app"))

    with pytest.raises(ValueError, match="Redis TLS"):
        Settings(redis_url=SecretStr("redis://redis.example:6379/0"))


def test_tls_runtime_requires_material_when_generation_is_disabled() -> None:
    with pytest.raises(TlsConfigurationError, match="certificate and key"):
        resolve_tls_config(TlsSettings(generate_self_signed=False))
