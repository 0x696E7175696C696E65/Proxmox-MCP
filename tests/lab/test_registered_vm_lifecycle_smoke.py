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
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolRequest,
    ToolResponse,
)
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


async def test_registered_vm_config_update_records_lab_contract(
    lab_mutation_tool_registry: ToolRegistry,
    lab_tool_context_factory: ContextFactory,
    lab_client: ProxmoxHttpApiClient,
    lab_audit_writer: InMemoryAuditWriter,
    optional_lab_node: str,
    disposable_lab_vmid: int,
) -> None:
    await _delete_vm_if_present(lab_client, optional_lab_node, disposable_lab_vmid)
    await _create_disposable_vm(lab_client, optional_lab_node, disposable_lab_vmid)
    task_store = RecordingTaskStore()
    approval_code = "lab-" + "approved"
    description = f"registered MCP lab update {disposable_lab_vmid}"
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
        parameters={"config": {"description": description}},
        options=RequestOptions(
            dry_run=False,
            idempotency_key=f"lab-update-vm-{disposable_lab_vmid}",
            approval_token=approval_code,
        ),
    )

    try:
        context = lab_tool_context_factory(
            request,
            lab_client,
            lab_audit_writer,
            proxmox_task_store=task_store,
        )
        response = await lab_mutation_tool_registry.execute(
            "update_vm_config",
            request,
            context,
        )
        config = await lab_client.get(
            f"/nodes/{optional_lab_node}/qemu/{disposable_lab_vmid}/config"
        )
    finally:
        await _delete_vm_if_present(lab_client, optional_lab_node, disposable_lab_vmid)

    assert isinstance(response, ToolResponse)
    raw_result: object = response.result
    assert isinstance(raw_result, dict)
    result = cast(dict[str, object], raw_result)
    assert result["result"] is None
    assert result["task_ref"] is None
    assert task_store.tasks == []
    assert isinstance(config, dict)
    assert config["description"] == description
    assert [event.result_status for event in lab_audit_writer.events] == ["started", "success"]


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
