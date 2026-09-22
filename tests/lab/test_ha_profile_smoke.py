from __future__ import annotations

import pytest

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig

pytestmark = pytest.mark.lab


async def test_ha_profile_reports_cluster_resources(
    lab_config: LabEnvironmentConfig,
    lab_client: ProxmoxHttpApiClient,
) -> None:
    if lab_config.profile != "pve-9-ha-enabled":
        pytest.skip("Select PROXMOX_MCP_LAB_PROFILE=pve-9-ha-enabled for HA profile tests")
    missing = lab_config.profile_missing_prerequisites()
    if missing:
        pytest.skip("; ".join(missing))

    status = await lab_client.get("/cluster/ha/status/current")

    assert isinstance(status, list)
