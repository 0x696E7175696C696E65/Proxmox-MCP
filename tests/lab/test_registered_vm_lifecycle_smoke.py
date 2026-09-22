from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import uuid4

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab_resources import DisposableProxmoxResources
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
    lab_resources: DisposableProxmoxResources,
    lab_audit_writer: InMemoryAuditWriter,
    optional_lab_node: str,
    disposable_lab_vmid: int,
) -> None:
    await lab_resources.delete_vm_if_present(disposable_lab_vmid)
    await lab_resources.create_vm(disposable_lab_vmid)
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
        await lab_resources.delete_vm_if_present(disposable_lab_vmid)

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
