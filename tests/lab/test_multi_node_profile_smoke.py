from __future__ import annotations

from typing import cast

import pytest

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig

pytestmark = pytest.mark.lab


async def test_multi_node_profile_requires_expected_cluster_size(
    lab_config: LabEnvironmentConfig,
    lab_client: ProxmoxHttpApiClient,
) -> None:
    if lab_config.profile != "pve-9-multi-node":
        pytest.skip("Select PROXMOX_MCP_LAB_PROFILE=pve-9-multi-node for multi-node tests")
    missing = lab_config.profile_missing_prerequisites()
    if missing:
        pytest.skip("; ".join(missing))

    nodes = await lab_client.get("/nodes")
    cluster_status = await lab_client.get("/cluster/status")

    assert isinstance(nodes, list)
    assert isinstance(cluster_status, list)
    expected_node_count = lab_config.expected_node_count or 2
    assert len(cast(list[object], nodes)) >= expected_node_count
