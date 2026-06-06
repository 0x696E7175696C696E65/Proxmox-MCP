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
from proxmox_mcp.ssh import InMemorySshClient, SshCommandPolicy, SshCommandResult
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
            resource_type="cluster",
            resource_id="ceph",
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
        ssh_command_policy=SshCommandPolicy(allowed_executables=frozenset({"ceph"})),
    )


def test_ceph_ha_pack_has_concrete_contracts() -> None:
    records = {record.name: record for record in domain_tool_pack_records("ceph_ha")}

    assert records["manage_ceph_pool"].endpoint_template == "/nodes/{node}/ceph/pool/{pool}"
    assert records["create_ceph_osd"].endpoint_template == "/nodes/{node}/ceph/osd"
    assert records["reweight_ceph_osd"].command_template == "ceph osd reweight {osd_id} {weight}"
    assert records["delete_ceph_mon"].endpoint_template == "/nodes/{node}/ceph/mon/{mon_id}"
    assert records["rebalance_ceph"].command_template == "ceph osd reweight-by-utilization"
    assert records["migrate_ha_resource"].endpoint_template == (
        "/cluster/ha/resources/{ha_resource_id}/migrate"
    )
    assert records["set_ha_group"].endpoint_template == "/cluster/ha/groups/{ha_group_id}"
    assert all(record.promotion_status == "live_supported" for record in records.values())


async def test_ceph_pool_live_call_uses_expected_api_path() -> None:
    registry = make_registry()
    request = make_request(parameters={"pool": "rbd", "payload": {"size": 3}}, dry_run=False)
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/ceph/pool/rbd": "UPID:ceph"})

    response = await registry.execute(
        "manage_ceph_pool",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].method == "PUT"
    assert client.requests[-1].path == "/nodes/pve-1/ceph/pool/rbd"
    assert client.requests[-1].data == {"size": 3}


async def test_ceph_rebalance_live_command_executes_when_policy_allows() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemorySshClient(
        command_results={
            "ceph osd reweight-by-utilization": SshCommandResult(exit_status=0, stdout="done")
        }
    )

    response = await registry.execute(
        "rebalance_ceph",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolResponse)
    _, command = client.executions[-1]
    assert command.command == "ceph osd reweight-by-utilization"


async def test_ceph_osd_reweight_live_command_executes_when_policy_allows() -> None:
    registry = make_registry()
    request = make_request(parameters={"osd_id": 1, "weight": "0.95"}, dry_run=False)
    client = InMemorySshClient(
        command_results={"ceph osd reweight 1 0.95": SshCommandResult(exit_status=0)}
    )

    response = await registry.execute(
        "reweight_ceph_osd",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolResponse)
    _, command = client.executions[-1]
    assert command.command == "ceph osd reweight 1 0.95"


async def test_ceph_ha_pack_requires_ha_resource_id_for_migration() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "migrate_ha_resource",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_ceph_ha_pack_dry_run_previews_ha_migration() -> None:
    registry = make_registry()
    request = make_request(parameters={"ha_resource_id": "vm:100", "payload": {"node": "pve-2"}})

    response = await registry.execute("migrate_ha_resource", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["endpoint"] == "/cluster/ha/resources/vm%3A100/migrate"
    assert result["payload"] == {"node": "pve-2"}
    assert result["risk"] == "high"
