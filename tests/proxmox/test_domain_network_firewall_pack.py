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
            resource_type="node",
            resource_id="pve-1",
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


def make_context(
    request: ToolRequest,
    proxmox_client: InMemoryProxmoxApiClient | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        proxmox_client=proxmox_client,
    )


def test_network_firewall_pack_has_precise_identifier_contracts() -> None:
    records = {record.name: record for record in domain_tool_pack_records("network_firewall")}

    assert records["delete_bridge"].endpoint_template == "/nodes/{node}/network/{iface}"
    assert records["update_sdn_zone"].endpoint_template == "/cluster/sdn/zones/{zone_id}"
    assert records["delete_firewall_rule"].endpoint_template == (
        "/cluster/firewall/rules/{rule_id}"
    )
    assert records["delete_firewall_alias"].endpoint_template == (
        "/cluster/firewall/aliases/{alias}"
    )
    assert records["update_ipset"].endpoint_template == "/cluster/firewall/ipset/{ipset}"
    assert all(record.promotion_status == "live_supported" for record in records.values())


async def test_network_firewall_pack_live_call_uses_expected_api_path() -> None:
    registry = make_registry()
    request = make_request(
        parameters={"iface": "vmbr10", "payload": {"autostart": 1}},
        dry_run=False,
    )
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/network/vmbr10": "UPID:network"})

    response = await registry.execute("update_bridge", request, make_context(request, client))

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].method == "PUT"
    assert client.requests[-1].path == "/nodes/pve-1/network/vmbr10"
    assert client.requests[-1].data == {"autostart": 1}


async def test_network_firewall_pack_dry_run_requires_firewall_identifier() -> None:
    registry = make_registry()
    request = make_request()

    response = await registry.execute("delete_firewall_rule", request, make_context(request))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"


async def test_network_firewall_pack_rejects_unsafe_sdn_identifier() -> None:
    registry = make_registry()
    request = make_request(parameters={"zone_id": "../dmz"}, dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("update_sdn_zone", request, make_context(request, client))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


def test_network_firewall_schema_uses_firewall_specific_fields() -> None:
    registry = make_registry()
    schemas = {schema.name: schema.parameters_schema for schema in registry.schemas()}
    delete_rule_schema = schemas["delete_firewall_rule"]
    update_ipset_schema = schemas["update_ipset"]

    assert delete_rule_schema is not None
    assert update_ipset_schema is not None
    delete_rule_properties = cast(dict[str, object], delete_rule_schema["properties"])
    update_ipset_properties = cast(dict[str, object], update_ipset_schema["properties"])
    assert "rule_id" in delete_rule_properties
    assert "iface" not in delete_rule_properties
    assert "ipset" in update_ipset_properties
