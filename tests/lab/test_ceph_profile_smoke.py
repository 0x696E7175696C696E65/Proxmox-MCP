from __future__ import annotations

from typing import cast

import pytest

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig

pytestmark = pytest.mark.lab


async def test_ceph_profile_reports_cluster_status(
    lab_config: LabEnvironmentConfig,
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
) -> None:
    if lab_config.profile != "pve-9-ceph-enabled":
        pytest.skip("Select PROXMOX_MCP_LAB_PROFILE=pve-9-ceph-enabled for Ceph profile tests")
    missing = lab_config.profile_missing_prerequisites()
    if missing:
        pytest.skip("; ".join(missing))

    status = await lab_client.get(f"/nodes/{optional_lab_node}/ceph/status")

    assert isinstance(status, dict)
    typed_status = cast(dict[str, object], status)
    assert typed_status
