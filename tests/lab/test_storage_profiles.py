from __future__ import annotations

from typing import cast

import pytest

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.tools.registry import ToolRegistry

pytestmark = pytest.mark.lab


async def test_local_directory_storage_content_discovery(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
) -> None:
    storages = await _cluster_storage_by_id(lab_client)
    local = storages.get("local")
    if local is None:
        pytest.skip("Lab profile does not expose local directory storage")

    assert local.get("type") == "dir"
    content = await lab_client.get(
        f"/nodes/{optional_lab_node}/storage/local/content",
        params={"content": "backup"},
    )

    assert isinstance(content, list)


async def test_local_lvm_storage_is_classified_without_generic_content_claim(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
) -> None:
    storages = await _cluster_storage_by_id(lab_client)
    local_lvm = storages.get("local-lvm")
    if local_lvm is None:
        pytest.skip("Lab profile does not expose local-lvm storage")

    assert local_lvm.get("type") == "lvmthin"
    status = await lab_client.get(f"/nodes/{optional_lab_node}/storage/local-lvm/status")

    assert isinstance(status, dict)
    typed_status = cast(dict[str, object], status)
    assert typed_status.get("type") == "lvmthin"


async def test_storage_profile_keeps_expansion_and_benchmark_unclaimed(
    lab_read_tool_registry: ToolRegistry,
) -> None:
    definitions = {
        definition.name: definition for definition in lab_read_tool_registry.definitions()
    }

    assert "expand_storage" not in definitions
    assert "benchmark_storage" not in definitions


async def _cluster_storage_by_id(
    lab_client: ProxmoxHttpApiClient,
) -> dict[str, dict[str, object]]:
    payload = await lab_client.get("/storage")
    assert isinstance(payload, list)

    storages: dict[str, dict[str, object]] = {}
    for item in cast(list[object], payload):
        if not isinstance(item, dict):
            continue
        storage = cast(dict[str, object], item)
        storage_id = storage.get("storage")
        if isinstance(storage_id, str):
            storages[storage_id] = storage
    return storages
