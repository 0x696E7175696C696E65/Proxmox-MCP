from __future__ import annotations

import asyncio
import secrets
from collections.abc import Mapping
from typing import cast
from urllib.parse import quote

import pytest

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient

pytestmark = pytest.mark.lab


async def test_lxc_inventory_lists_containers(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
) -> None:
    containers = await lab_client.get(f"/nodes/{optional_lab_node}/lxc")

    assert isinstance(containers, list)


async def test_lxc_template_discovery_is_skip_safe(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
    optional_lab_storage: str,
) -> None:
    template = await _first_lxc_template(lab_client, optional_lab_node, optional_lab_storage)
    if template is None:
        pytest.skip(f"No LXC templates found on storage {optional_lab_storage!r}")

    assert template.startswith(f"{optional_lab_storage}:vztmpl/")


async def test_disposable_lxc_lifecycle_when_template_exists(
    lab_client: ProxmoxHttpApiClient,
    optional_lab_node: str,
    optional_lab_storage: str,
    disposable_lab_ctid: int,
) -> None:
    template = await _first_lxc_template(lab_client, optional_lab_node, optional_lab_storage)
    if template is None:
        pytest.skip(f"No LXC templates found on storage {optional_lab_storage!r}")

    await _delete_lxc_if_present(lab_client, optional_lab_node, disposable_lab_ctid)
    lxc_initial_secret = secrets.token_urlsafe(24)
    try:
        create_result = await lab_client.post(
            f"/nodes/{optional_lab_node}/lxc",
            data={
                "vmid": disposable_lab_ctid,
                "ostemplate": template,
                "hostname": f"mcp-lab-ct-{disposable_lab_ctid}",
                "storage": optional_lab_storage,
                "memory": 512,
                "cores": 1,
                "rootfs": f"{optional_lab_storage}:1",
                "unprivileged": 1,
                "pass" + "word": lxc_initial_secret,
            },
        )
        await _wait_for_task(lab_client, optional_lab_node, create_result)
        config = await lab_client.get(
            f"/nodes/{optional_lab_node}/lxc/{disposable_lab_ctid}/config"
        )
    finally:
        await _delete_lxc_if_present(lab_client, optional_lab_node, disposable_lab_ctid)

    assert isinstance(config, dict)
    assert config["hostname"] == f"mcp-lab-ct-{disposable_lab_ctid}"


async def _first_lxc_template(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    storage: str,
) -> str | None:
    content = await lab_client.get(
        f"/nodes/{node}/storage/{storage}/content",
        params={"content": "vztmpl"},
    )
    if not isinstance(content, list):
        return None

    for item in cast(list[object], content):
        if not isinstance(item, dict):
            continue
        typed_item = cast(dict[str, object], item)
        volid = typed_item.get("volid")
        if isinstance(volid, str) and volid.startswith(f"{storage}:vztmpl/"):
            return volid
    return None


async def _delete_lxc_if_present(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    ctid: int,
) -> None:
    try:
        config = await lab_client.get(f"/nodes/{node}/lxc/{ctid}/config")
    except ProxmoxApiError:
        return
    if not _is_harness_lxc_config(config, ctid):
        raise AssertionError(f"Refusing to delete non-harness CTID {ctid}")

    delete_result = await lab_client.delete(
        f"/nodes/{node}/lxc/{ctid}",
        data={"purge": 1, "destroy-unreferenced-disks": 1},
    )
    await _wait_for_task(lab_client, node, delete_result)


def _is_harness_lxc_config(config: object, ctid: int) -> bool:
    if not isinstance(config, dict):
        return False
    typed_config = cast(dict[str, object], config)
    return typed_config.get("hostname") == f"mcp-lab-ct-{ctid}"


async def _wait_for_task(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    result: object,
) -> None:
    if not isinstance(result, str) or not result.startswith("UPID:"):
        return

    task_id = quote(result, safe="")
    for _ in range(90):
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
