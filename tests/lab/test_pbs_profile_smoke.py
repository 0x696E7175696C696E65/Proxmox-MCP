from __future__ import annotations

from typing import cast

import pytest

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig

pytestmark = pytest.mark.lab


async def test_pbs_profile_reports_configured_repository(
    lab_config: LabEnvironmentConfig,
    lab_client: ProxmoxHttpApiClient,
) -> None:
    if lab_config.profile != "pve-9-pbs-enabled":
        pytest.skip("Select PROXMOX_MCP_LAB_PROFILE=pve-9-pbs-enabled for PBS profile tests")
    missing = lab_config.profile_missing_prerequisites()
    if missing:
        pytest.skip("; ".join(missing))

    payload = await lab_client.get("/storage")

    assert isinstance(payload, list)
    repository = lab_config.pbs_repository_id
    assert repository is not None
    storages: dict[object, dict[str, object]] = {}
    for item in cast(list[object], payload):
        if not isinstance(item, dict):
            continue
        storage = cast(dict[str, object], item)
        storages[storage.get("storage")] = storage
    assert repository in storages
    assert storages[repository].get("type") == "pbs"
