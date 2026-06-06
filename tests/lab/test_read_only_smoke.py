from __future__ import annotations

from collections.abc import Iterable

import pytest

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient

pytestmark = pytest.mark.lab


@pytest.mark.asyncio
async def test_lab_cluster_and_node_discovery(lab_client: ProxmoxHttpApiClient) -> None:
    cluster_status = await lab_client.get("/cluster/status")
    nodes = await lab_client.get("/nodes")

    assert _is_sequence(cluster_status)
    assert _is_sequence(nodes)


@pytest.mark.asyncio
async def test_lab_guest_and_storage_discovery(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
) -> None:
    qemu = await lab_client.get(f"/nodes/{optional_lab_node}/qemu")
    lxc = await lab_client.get(f"/nodes/{optional_lab_node}/lxc")
    storage = await lab_client.get(f"/nodes/{optional_lab_node}/storage")

    assert _is_sequence(qemu)
    assert _is_sequence(lxc)
    assert _is_sequence(storage)


@pytest.mark.asyncio
async def test_lab_storage_content_discovery(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
    optional_lab_storage: str,
) -> None:
    content = await lab_client.get(
        f"/nodes/{optional_lab_node}/storage/{optional_lab_storage}/content"
    )

    assert _is_sequence(content)


@pytest.mark.asyncio
async def test_lab_access_and_permission_discovery(
    lab_client: ProxmoxHttpApiClient,
) -> None:
    users = await lab_client.get("/access/users")
    roles = await lab_client.get("/access/roles")
    acl = await lab_client.get("/access/acl")

    assert _is_sequence(users)
    assert _is_sequence(roles)
    assert _is_sequence(acl)


@pytest.mark.asyncio
async def test_lab_ceph_ha_and_firewall_discovery(
    lab_client: ProxmoxHttpApiClient,
) -> None:
    ha_status = await lab_client.get("/cluster/ha/status/current")
    firewall_options = await lab_client.get("/cluster/firewall/options")

    assert _is_sequence(ha_status)
    assert isinstance(firewall_options, dict)

    ceph_status = await lab_client.get("/cluster/ceph/status")
    assert isinstance(ceph_status, dict)


def _is_sequence(value: object) -> bool:
    return isinstance(value, Iterable) and not isinstance(value, (str, bytes, dict))
