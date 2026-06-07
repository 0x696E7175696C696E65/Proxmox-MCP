from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol, cast
from urllib.parse import quote
from uuid import uuid4

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.reliability import ProxmoxTask, ProxmoxTaskStore
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolRegistry

pytestmark = pytest.mark.lab


class ContextFactory(Protocol):
    def __call__(
        self,
        request: ToolRequest,
        lab_client: ProxmoxHttpApiClient,
        audit_writer: InMemoryAuditWriter,
        *,
        authenticated: bool = True,
        proxmox_task_store: ProxmoxTaskStore | None = None,
    ) -> ToolExecutionContext: ...


class RecordingTaskStore:
    def __init__(self) -> None:
        self.tasks: list[ProxmoxTask] = []

    async def record_task(
        self,
        *,
        upid: str,
        operation: str,
        method: str,
        endpoint: str,
        target: dict[str, object],
        request_fingerprint: str,
        idempotency_key: str | None,
        status: str = "running",
        retryable: bool = True,
        last_observed_state: str | None = None,
    ) -> ProxmoxTask:
        now = datetime.now(UTC)
        task = ProxmoxTask(
            task_id=f"task_{uuid4().hex}",
            upid=upid,
            operation=operation,
            method=method,
            endpoint=endpoint,
            target=target,
            request_fingerprint=request_fingerprint,
            idempotency_key=idempotency_key,
            status=status,
            retryable=retryable,
            last_observed_state=last_observed_state,
            created_at=now,
            updated_at=now,
        )
        self.tasks.append(task)
        return task

    async def get_by_upid(self, upid: str) -> ProxmoxTask:
        for task in self.tasks:
            if task.upid == upid:
                return task
        raise KeyError(upid)


async def test_registered_vm_backup_creates_listable_artifact(
    lab_mutation_tool_registry: ToolRegistry,
    lab_tool_context_factory: ContextFactory,
    lab_client: ProxmoxHttpApiClient,
    lab_audit_writer: InMemoryAuditWriter,
    optional_lab_node: str,
    optional_lab_storage: str,
    disposable_lab_vmid: int,
) -> None:
    before: set[str] = set()
    task_store = RecordingTaskStore()
    new_backups: list[str] = []

    try:
        await _delete_vm_if_present(lab_client, optional_lab_node, disposable_lab_vmid)
        await _create_disposable_vm(lab_client, optional_lab_node, disposable_lab_vmid)
        before = await _backup_volids(lab_client, optional_lab_node, optional_lab_storage)
        request = ToolRequest(
            actor=Actor(user_id="lab_user", agent_id="lab_agent", tenant_id="lab_tenant"),
            target=Target(
                tenant_id="lab_tenant",
                cluster="lab",
                node=optional_lab_node,
                resource_type="vm",
                resource_id=str(disposable_lab_vmid),
                vmid=disposable_lab_vmid,
            ),
            parameters={"storage": optional_lab_storage, "mode": "snapshot"},
            options=RequestOptions(
                dry_run=False,
                idempotency_key=f"lab-backup-vm-{disposable_lab_vmid}",
            ),
        )
        response = await lab_mutation_tool_registry.execute(
            "run_vm_backup",
            request,
            lab_tool_context_factory(
                request,
                lab_client,
                lab_audit_writer,
                proxmox_task_store=task_store,
            ),
        )
        assert isinstance(response, ToolResponse)
        raw_result: object = response.result
        assert isinstance(raw_result, dict)
        result = cast(dict[str, object], raw_result)
        upid = result["result"]
        assert isinstance(upid, str)
        await _wait_for_task(lab_client, optional_lab_node, upid)
        after = await _backup_volids(lab_client, optional_lab_node, optional_lab_storage)
        new_backups = [
            volid
            for volid in sorted(after - before)
            if _is_backup_for_vmid(volid, disposable_lab_vmid)
        ]
    finally:
        cleanup_candidates = await _backup_volids(
            lab_client,
            optional_lab_node,
            optional_lab_storage,
        )
        for volid in sorted(cleanup_candidates - before):
            if not _is_backup_for_vmid(volid, disposable_lab_vmid):
                continue
            await _delete_storage_content(lab_client, optional_lab_node, volid)
        await _delete_vm_if_present(lab_client, optional_lab_node, disposable_lab_vmid)

    assert new_backups
    assert result["task_ref"] == task_store.tasks[0].task_id
    assert task_store.tasks[0].operation == "run_vm_backup"
    assert task_store.tasks[0].endpoint == f"/nodes/{optional_lab_node}/vzdump"


async def test_verify_backup_remains_guarded_without_backend_contract(
    lab_read_tool_registry: ToolRegistry,
) -> None:
    definitions = {
        definition.name: definition for definition in lab_read_tool_registry.definitions()
    }

    assert "verify_backup" not in definitions


async def _create_disposable_vm(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    vmid: int,
) -> None:
    create_result = await lab_client.post(
        f"/nodes/{node}/qemu",
        data={
            "vmid": vmid,
            "name": f"mcp-lab-{vmid}",
            "memory": 512,
            "cores": 1,
            "ostype": "l26",
        },
    )
    await _wait_for_task(lab_client, node, create_result)


async def _delete_vm_if_present(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    vmid: int,
) -> None:
    try:
        config = await lab_client.get(f"/nodes/{node}/qemu/{vmid}/config")
    except ProxmoxApiError:
        return
    if not _is_harness_vm_config(config, vmid):
        raise AssertionError(f"Refusing to delete non-harness VMID {vmid}")

    delete_result = await lab_client.delete(
        f"/nodes/{node}/qemu/{vmid}",
        data={"purge": 1, "destroy-unreferenced-disks": 1},
    )
    await _wait_for_task(lab_client, node, delete_result)


def _is_harness_vm_config(config: object, vmid: int) -> bool:
    if not isinstance(config, dict):
        return False
    typed_config = cast(dict[str, object], config)
    return typed_config.get("name") == f"mcp-lab-{vmid}"


async def _backup_volids(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    storage: str,
) -> set[str]:
    content = await lab_client.get(
        f"/nodes/{node}/storage/{storage}/content",
        params={"content": "backup"},
    )
    if not isinstance(content, list):
        return set()

    volids: set[str] = set()
    for item in cast(list[object], content):
        if not isinstance(item, dict):
            continue
        volid = cast(dict[str, object], item).get("volid")
        if isinstance(volid, str):
            volids.add(volid)
    return volids


def _is_backup_for_vmid(volid: str, vmid: int) -> bool:
    return f"/vzdump-qemu-{vmid}-" in volid or f":backup/vzdump-qemu-{vmid}-" in volid


async def _delete_storage_content(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    volid: str,
) -> None:
    try:
        await lab_client.delete(
            f"/nodes/{node}/storage/{volid.split(':', 1)[0]}/content/{quote(volid, safe='')}"
        )
    except ProxmoxApiError:
        return


async def _wait_for_task(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    result: object,
) -> None:
    if not isinstance(result, str) or not result.startswith("UPID:"):
        return

    task_id = quote(result, safe="")
    for _ in range(120):
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
