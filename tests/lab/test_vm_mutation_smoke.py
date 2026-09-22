from __future__ import annotations

import pytest

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab_resources import DisposableProxmoxResources

pytestmark = pytest.mark.lab


@pytest.mark.asyncio
async def test_lab_create_update_and_delete_disposable_vm(
    lab_client: ProxmoxHttpApiClient,
    lab_resources: DisposableProxmoxResources,
    optional_lab_node: str,
    disposable_lab_vmid: int,
) -> None:
    await lab_resources.delete_vm_if_present(disposable_lab_vmid)

    try:
        await lab_resources.create_vm(disposable_lab_vmid)

        config = await lab_client.get(
            f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config"
        )
        assert isinstance(config, dict)
        assert config["name"] == f"mcp-lab-{disposable_lab_vmid}"

        update_result = await lab_client.put(
            f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config",
            data={"description": "enterprise-proxmox-mcp disposable lab VM"},
        )
        await lab_resources.wait_for_task(update_result)

        updated_config = await lab_client.get(
            f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config"
        )
        assert isinstance(updated_config, dict)
        assert updated_config["description"] == "enterprise-proxmox-mcp disposable lab VM"
    finally:
        await lab_resources.delete_vm_if_present(disposable_lab_vmid)

    with pytest.raises(ProxmoxApiError):
        await lab_client.get(f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config")
