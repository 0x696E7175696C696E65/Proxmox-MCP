from __future__ import annotations

import pytest

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.proxmox.lab_resources import (
    DisposableProxmoxResources,
    LabResourceError,
    LabTaskTimeoutError,
)


class FakeLabClient:
    def __init__(self) -> None:
        self.responses: dict[str, object] = {}
        self.deleted: list[tuple[str, dict[str, object] | None]] = []
        self.posts: list[tuple[str, dict[str, object] | None]] = []

    async def get(self, path: str, *, params: dict[str, object] | None = None) -> object:
        _ = params
        if path not in self.responses:
            raise ProxmoxApiError("missing", retryable=False)
        return self.responses[path]

    async def post(self, path: str, *, data: dict[str, object] | None = None) -> object:
        self.posts.append((path, data))
        return "UPID:pve-a:1:2:3:mcp-lab:task:"

    async def delete(self, path: str, *, data: dict[str, object] | None = None) -> object:
        self.deleted.append((path, data))
        return "UPID:pve-a:1:2:3:mcp-lab:task:"


async def test_lab_resources_refuse_to_delete_unowned_vm() -> None:
    client = FakeLabClient()
    client.responses["/nodes/pve-a/qemu"] = [{"vmid": 9001}]
    client.responses["/nodes/pve-a/qemu/9001/config"] = {"name": "production"}
    resources = DisposableProxmoxResources(client=client, node="pve-a")

    with pytest.raises(LabResourceError, match="non-harness VMID"):
        await resources.delete_vm_if_present(9001)

    assert client.deleted == []


async def test_lab_resources_do_not_treat_auth_errors_as_absent_resources() -> None:
    client = FakeLabClient()
    resources = DisposableProxmoxResources(client=client, node="pve-a")

    with pytest.raises(ProxmoxApiError):
        await resources.delete_vm_if_present(9001)

    assert client.deleted == []


async def test_lab_resources_delete_owned_vm_and_record_cleanup() -> None:
    client = FakeLabClient()
    client.responses["/nodes/pve-a/qemu"] = [{"vmid": 9001}]
    client.responses["/nodes/pve-a/qemu/9001/config"] = {"name": "mcp-lab-9001"}
    client.responses["/nodes/pve-a/tasks/UPID%3Apve-a%3A1%3A2%3A3%3Amcp-lab%3Atask%3A/status"] = {
        "status": "stopped",
        "exitstatus": "OK",
    }
    resources = DisposableProxmoxResources(client=client, node="pve-a")

    cleanup = await resources.delete_vm_if_present(9001)

    assert client.deleted == [
        ("/nodes/pve-a/qemu/9001", {"purge": 1, "destroy-unreferenced-disks": 1})
    ]
    assert cleanup == {"resource_type": "vm", "resource_id": "9001", "cleanup": "deleted"}


async def test_lab_resources_treat_missing_inventory_entry_as_absent() -> None:
    client = FakeLabClient()
    client.responses["/nodes/pve-a/qemu"] = []
    resources = DisposableProxmoxResources(client=client, node="pve-a")

    cleanup = await resources.delete_vm_if_present(9001)

    assert cleanup == {"resource_type": "vm", "resource_id": "9001", "cleanup": "absent"}
    assert client.deleted == []


async def test_lab_resources_timeout_reports_sanitized_task_error() -> None:
    client = FakeLabClient()
    client.responses["/nodes/pve-a/tasks/UPID%3Apve-a%3A1%3A2%3A3%3Amcp-lab%3Atask%3A/status"] = {
        "status": "running"
    }
    resources = DisposableProxmoxResources(client=client, node="pve-a", task_poll_attempts=1)

    with pytest.raises(LabTaskTimeoutError) as exc_info:
        await resources.wait_for_task("UPID:pve-a:1:2:3:mcp-lab:task:")

    assert exc_info.value.evidence == {
        "task_status": "timeout",
        "node": "pve-a",
        "attempts": 1,
    }
