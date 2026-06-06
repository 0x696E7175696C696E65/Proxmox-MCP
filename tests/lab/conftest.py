from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig


@pytest.fixture(scope="session")
def lab_config() -> LabEnvironmentConfig:
    config = LabEnvironmentConfig.from_env(os.environ)
    if not config.enabled:
        pytest.skip(config.skip_reason or "Proxmox lab tests are not enabled")
    return config


@pytest.fixture(scope="session")
def lab_client(lab_config: LabEnvironmentConfig) -> ProxmoxHttpApiClient:
    if lab_config.api_endpoint is None:
        pytest.skip("Missing Proxmox lab API endpoint")
    if lab_config.token_id is None or lab_config.token_secret is None:
        pytest.skip("Missing Proxmox lab API token")

    return ProxmoxHttpApiClient(
        api_endpoint=lab_config.api_endpoint,
        token_id=lab_config.token_id,
        token_secret=lab_config.token_secret,
        tls_verify=lab_config.tls_verify,
    )


@pytest.fixture
def optional_lab_node(lab_config: LabEnvironmentConfig) -> Iterator[str]:
    if lab_config.node is None:
        pytest.skip("Set PROXMOX_MCP_LAB_NODE to run node-scoped lab smoke tests")
    yield lab_config.node


@pytest.fixture
def optional_lab_storage(lab_config: LabEnvironmentConfig) -> Iterator[str]:
    if lab_config.storage_id is None:
        pytest.skip("Set PROXMOX_MCP_LAB_STORAGE to run storage-scoped lab smoke tests")
    yield lab_config.storage_id


@pytest.fixture
def lab_mutations_enabled(lab_config: LabEnvironmentConfig) -> bool:
    _ = lab_config
    if os.environ.get("PROXMOX_MCP_LAB_MUTATIONS_ENABLED", "").strip().lower() != "true":
        pytest.skip("Set PROXMOX_MCP_LAB_MUTATIONS_ENABLED=true to run mutation lab tests")
    return True


@pytest.fixture
def lab_destructive_enabled(lab_mutations_enabled: bool) -> bool:
    _ = lab_mutations_enabled
    if os.environ.get("PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED", "").strip().lower() != "true":
        pytest.skip("Set PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED=true to run destructive lab tests")
    return True
