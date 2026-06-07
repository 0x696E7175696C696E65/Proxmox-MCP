from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast
from urllib.parse import quote

from proxmox_mcp.proxmox.client import ProxmoxApiError


class LabResourceClient(Protocol):
    async def get(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
    ) -> object: ...

    async def post(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object: ...

    async def delete(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object: ...


class LabResourceError(RuntimeError):
    pass


class LabTaskTimeoutError(LabResourceError):
    def __init__(self, message: str, *, evidence: dict[str, object]) -> None:
        super().__init__(message)
        self.evidence = evidence


@dataclass(frozen=True, slots=True)
class DisposableProxmoxResources:
    client: LabResourceClient
    node: str
    task_poll_attempts: int = 90
    task_poll_interval_seconds: float = 1

    async def create_vm(
        self,
        vmid: int,
        *,
        memory: int = 512,
        cores: int = 1,
    ) -> dict[str, object]:
        result = await self.client.post(
            f"/nodes/{self.node}/qemu",
            data={
                "vmid": vmid,
                "name": vm_name(vmid),
                "memory": memory,
                "cores": cores,
                "ostype": "l26",
            },
        )
        await self.wait_for_task(result)
        return {"resource_type": "vm", "resource_id": str(vmid), "cleanup": "created"}

    async def delete_vm_if_present(self, vmid: int) -> dict[str, object]:
        try:
            config = await self.client.get(f"/nodes/{self.node}/qemu/{vmid}/config")
        except ProxmoxApiError as exc:
            if _is_not_found(exc):
                return {"resource_type": "vm", "resource_id": str(vmid), "cleanup": "absent"}
            raise
        if not is_harness_vm_config(config, vmid):
            raise LabResourceError(f"Refusing to delete non-harness VMID {vmid}")
        result = await self.client.delete(
            f"/nodes/{self.node}/qemu/{vmid}",
            data={"purge": 1, "destroy-unreferenced-disks": 1},
        )
        await self.wait_for_task(result)
        return {"resource_type": "vm", "resource_id": str(vmid), "cleanup": "deleted"}

    async def create_lxc(
        self,
        ctid: int,
        *,
        template: str,
        storage: str,
        password: str,
        memory: int = 512,
        cores: int = 1,
    ) -> dict[str, object]:
        result = await self.client.post(
            f"/nodes/{self.node}/lxc",
            data={
                "vmid": ctid,
                "ostemplate": template,
                "hostname": lxc_hostname(ctid),
                "storage": storage,
                "memory": memory,
                "cores": cores,
                "rootfs": f"{storage}:1",
                "unprivileged": 1,
                "pass" + "word": password,
            },
        )
        await self.wait_for_task(result)
        return {"resource_type": "lxc", "resource_id": str(ctid), "cleanup": "created"}

    async def delete_lxc_if_present(self, ctid: int) -> dict[str, object]:
        try:
            config = await self.client.get(f"/nodes/{self.node}/lxc/{ctid}/config")
        except ProxmoxApiError as exc:
            if _is_not_found(exc):
                return {"resource_type": "lxc", "resource_id": str(ctid), "cleanup": "absent"}
            raise
        if not is_harness_lxc_config(config, ctid):
            raise LabResourceError(f"Refusing to delete non-harness CTID {ctid}")
        result = await self.client.delete(
            f"/nodes/{self.node}/lxc/{ctid}",
            data={"purge": 1, "destroy-unreferenced-disks": 1},
        )
        await self.wait_for_task(result)
        return {"resource_type": "lxc", "resource_id": str(ctid), "cleanup": "deleted"}

    async def first_lxc_template(self, storage: str) -> str | None:
        content = await self.client.get(
            f"/nodes/{self.node}/storage/{storage}/content",
            params={"content": "vztmpl"},
        )
        if not isinstance(content, list):
            return None
        for item in cast(list[object], content):
            if not isinstance(item, dict):
                continue
            volid = cast(dict[str, object], item).get("volid")
            if isinstance(volid, str) and volid.startswith(f"{storage}:vztmpl/"):
                return volid
        return None

    async def wait_for_task(self, result: object) -> None:
        if not isinstance(result, str) or not result.startswith("UPID:"):
            return
        task_id = quote(result, safe="")
        for _ in range(self.task_poll_attempts):
            status = await self.client.get(f"/nodes/{self.node}/tasks/{task_id}/status")
            if not isinstance(status, dict):
                await asyncio.sleep(self.task_poll_interval_seconds)
                continue
            task_status = cast(Mapping[str, object], status)
            if task_status.get("status") == "stopped":
                exitstatus = task_status.get("exitstatus")
                if exitstatus not in {None, "OK"}:
                    raise LabResourceError(f"Proxmox task failed: {exitstatus}")
                return
            await asyncio.sleep(self.task_poll_interval_seconds)
        raise LabTaskTimeoutError(
            "Timed out waiting for Proxmox task",
            evidence={
                "task_status": "timeout",
                "node": self.node,
                "attempts": self.task_poll_attempts,
            },
        )


def vm_name(vmid: int) -> str:
    return f"mcp-lab-{vmid}"


def lxc_hostname(ctid: int) -> str:
    return f"mcp-lab-ct-{ctid}"


def is_harness_vm_config(config: object, vmid: int) -> bool:
    if not isinstance(config, dict):
        return False
    return cast(dict[str, object], config).get("name") == vm_name(vmid)


def is_harness_lxc_config(config: object, ctid: int) -> bool:
    if not isinstance(config, dict):
        return False
    return cast(dict[str, object], config).get("hostname") == lxc_hostname(ctid)


def _is_not_found(exc: ProxmoxApiError) -> bool:
    return exc.status_code == 404 or exc.error_code == "NOT_FOUND"
