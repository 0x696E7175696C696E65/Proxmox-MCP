from __future__ import annotations

from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    InMemoryProxmoxApiClient,
    domain_tool_pack_records,
    register_domain_completion_tools,
)
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.ssh import InMemorySshClient, SshCommandPolicy
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolGuardDecision, ToolRegistry


class AllowGuard:
    async def evaluate(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolGuardDecision:
        _ = definition, request, context
        return ToolGuardDecision.allowed()


def make_registry() -> ToolRegistry:
    registry = ToolRegistry(guard=AllowGuard())
    register_domain_completion_tools(registry)
    return registry


def make_request(
    *,
    parameters: dict[str, object] | None = None,
    dry_run: bool = True,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            cluster="lab",
            node="pve-1",
            resource_type="vm",
            resource_id="100",
            vmid=100,
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


def make_context(
    request: ToolRequest,
    *,
    proxmox_client: InMemoryProxmoxApiClient | None = None,
    ssh_client: InMemorySshClient | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        proxmox_client=proxmox_client,
        ssh_client=ssh_client,
        ssh_command_policy=SshCommandPolicy(allowed_executables=frozenset({"pct"})),
    )


def test_vm_lxc_pack_has_concrete_execution_contracts() -> None:
    records = {record.name: record for record in domain_tool_pack_records("vm_lxc")}

    assert records["create_vm"].endpoint_template == "/nodes/{node}/qemu"
    assert records["clone_vm"].endpoint_template == "/nodes/{node}/qemu/{vmid}/clone"
    assert records["resize_vm_disk"].endpoint_template == "/nodes/{node}/qemu/{vmid}/resize"
    assert records["create_lxc"].endpoint_template == "/nodes/{node}/lxc"
    assert records["clone_lxc"].endpoint_template == "/nodes/{node}/lxc/{vmid}/clone"
    assert records["restore_lxc"].endpoint_template == "/nodes/{node}/lxc"

    assert all(record.live_supported for record in records.values())
    assert all(record.promotion_status == "live_supported" for record in records.values())
    assert records["enter_lxc_console"].command_template == "pct enter {vmid}"


async def test_vm_lxc_pack_dry_run_previews_endpoint_payload_and_impact() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"target": "pve-2", "online": 1}})

    response = await registry.execute("migrate_vm", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["endpoint"] == "/nodes/pve-1/qemu/100/migrate"
    assert result["payload"] == {"target": "pve-2", "online": 1}
    assert result["risk"] == "high"
    assert result["live_supported"] is True
    assert isinstance(result["impact"], dict)
    assert (
        result["rollback_guidance"] == "Verify target state and rollback path before live execution"
    )


async def test_vm_lxc_pack_live_call_uses_expected_api_path() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"disk": "scsi0", "size": "+10G"}}, dry_run=False)
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/qemu/100/resize": "UPID:resize"})

    response = await registry.execute(
        "resize_vm_disk",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].method == "POST"
    assert client.requests[-1].path == "/nodes/pve-1/qemu/100/resize"
    assert client.requests[-1].data == {"disk": "scsi0", "size": "+10G"}


async def test_lxc_console_live_execution_remains_guarded_for_session_contract() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemorySshClient()

    response = await registry.execute(
        "enter_lxc_console",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
    assert client.executions == []
