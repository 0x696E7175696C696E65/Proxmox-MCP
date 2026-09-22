from __future__ import annotations

import secrets

import pytest

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig
from proxmox_mcp.proxmox.lab_resources import DisposableProxmoxResources

pytestmark = pytest.mark.lab


async def test_lxc_inventory_lists_containers(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
) -> None:
    containers = await lab_client.get(f"/nodes/{optional_lab_node}/lxc")

    assert isinstance(containers, list)


async def test_lxc_template_discovery_is_skip_safe(
    lab_config: LabEnvironmentConfig,
    lab_resources: DisposableProxmoxResources,
    optional_lab_storage: str,
) -> None:
    template = await _configured_or_first_lxc_template(
        lab_config,
        lab_resources,
        optional_lab_storage,
    )
    if template is None:
        pytest.skip(f"No LXC templates found on storage {optional_lab_storage!r}")

    template_storage = lab_config.lxc_template_storage_id or optional_lab_storage
    assert template.startswith(f"{template_storage}:vztmpl/")


async def test_disposable_lxc_lifecycle_when_template_exists(
    lab_config: LabEnvironmentConfig,
    lab_client: ProxmoxHttpApiClient,
    lab_resources: DisposableProxmoxResources,
    optional_lab_node: str,
    optional_lab_storage: str,
    disposable_lab_ctid: int,
) -> None:
    template = await _configured_or_first_lxc_template(
        lab_config,
        lab_resources,
        optional_lab_storage,
    )
    if template is None:
        pytest.skip(f"No LXC templates found on storage {optional_lab_storage!r}")

    await lab_resources.delete_lxc_if_present(disposable_lab_ctid)
    lxc_initial_secret = secrets.token_urlsafe(24)
    try:
        await lab_resources.create_lxc(
            disposable_lab_ctid,
            template=template,
            storage=optional_lab_storage,
            password=lxc_initial_secret,
        )
        config = await lab_client.get(
            f"/nodes/{optional_lab_node}/lxc/{disposable_lab_ctid}/config"
        )
    finally:
        await lab_resources.delete_lxc_if_present(disposable_lab_ctid)

    assert isinstance(config, dict)
    assert config["hostname"] == f"mcp-lab-ct-{disposable_lab_ctid}"


async def _configured_or_first_lxc_template(
    lab_config: LabEnvironmentConfig,
    lab_resources: DisposableProxmoxResources,
    storage: str,
) -> str | None:
    if lab_config.lxc_template_volid is not None:
        return lab_config.lxc_template_volid
    return await lab_resources.first_lxc_template(lab_config.lxc_template_storage_id or storage)
