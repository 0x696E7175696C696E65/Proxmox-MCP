from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import cast
from urllib.parse import quote

import pytest

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient

pytestmark = pytest.mark.lab


@pytest.mark.asyncio
async def test_lab_create_update_and_delete_disposable_vm(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
    disposable_lab_vmid: int,
) -> None:
    await _delete_vm_if_present(lab_client, optional_lab_node, disposable_lab_vmid)

    create_result = await lab_client.post(
        f"/nodes/{optional_lab_node}/qemu",
        data={
            "vmid": disposable_lab_vmid,
            "name": f"mcp-lab-{disposable_lab_vmid}",
            "memory": 512,
            "cores": 1,
            "ostype": "l26",
        },
    )
    await _wait_for_task(lab_client, optional_lab_node, create_result)

    config = await lab_client.get(f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config")
    assert isinstance(config, dict)
    assert config["name"] == f"mcp-lab-{disposable_lab_vmid}"

    update_result = await lab_client.put(
        f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config",
        data={"description": "enterprise-proxmox-mcp disposable lab VM"},
    )
    await _wait_for_task(lab_client, optional_lab_node, update_result)

    updated_config = await lab_client.get(
        f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config"
    )
    assert isinstance(updated_config, dict)
    assert updated_config["description"] == "enterprise-proxmox-mcp disposable lab VM"

    delete_result = await lab_client.delete(
        f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}",
        data={"purge": 1, "destroy-unreferenced-disks": 1},
    )
    await _wait_for_task(lab_client, optional_lab_node, delete_result)

    with pytest.raises(ProxmoxApiError):
        await lab_client.get(f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config")


async def _delete_vm_if_present(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    vmid: int,
) -> None:
    try:
        await lab_client.get(f"/nodes/{node}/qemu/{vmid}/config")
    except ProxmoxApiError:
        return

    delete_result = await lab_client.delete(
        f"/nodes/{node}/qemu/{vmid}",
        data={"purge": 1, "destroy-unreferenced-disks": 1},
    )
    await _wait_for_task(lab_client, node, delete_result)


async def _wait_for_task(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    result: object,
) -> None:
    if not isinstance(result, str) or not result.startswith("UPID:"):
        return

    task_id = quote(result, safe="")
    for _ in range(60):
        status = await lab_client.get(f"/nodes/{node}/tasks/{task_id}/status")
        if not isinstance(status, dict):
            await asyncio.sleep(1)
            continue

        task_status = cast(Mapping[str, object], status)
        if task_status.get("status") == "stopped":
            exitstatus = task_status.get("exitstatus")
            if exitstatus not in {None, "OK"}:
                raise AssertionError(f"Proxmox task failed: {exitstatus}")
            return
        await asyncio.sleep(1)

    raise AssertionError("Timed out waiting for Proxmox task")
