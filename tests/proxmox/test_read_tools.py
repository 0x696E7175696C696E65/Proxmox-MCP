from __future__ import annotations

from datetime import UTC, datetime, timedelta

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    READ_ONLY_TOOL_SPECS,
    InMemoryProxmoxApiClient,
    register_read_only_tools,
)
from proxmox_mcp.rbac import Role, RoleAssignment, Scope
from proxmox_mcp.schemas.envelope import Actor, Target, ToolErrorResponse, ToolRequest, ToolResponse
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolRegistry


def make_session() -> AuthenticatedSession:
    issued_at = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess_readonly",
        identity=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        auth_method="service_token",
        status="active",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=15),
    )


def make_registry() -> ToolRegistry:
    registry = ToolRegistry(
        guard=SecurityPlaneGuard(
            role_assignments=(
                RoleAssignment(
                    actor_user_id="user_1",
                    actor_agent_id="agent_1",
                    role=Role(name="Read Everything", permissions=frozenset({"*"})),
                    scope=Scope(tenant_id="tenant_1"),
                ),
            )
        )
    )
    register_read_only_tools(registry)
    return registry


def make_context(
    request: ToolRequest,
    client: InMemoryProxmoxApiClient | None,
    writer: InMemoryAuditWriter,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=writer,
        authenticated_session=make_session(),
        proxmox_client=client,
    )


def make_request(
    *,
    node: str | None = "pve-1",
    resource_type: str = "vm",
    resource_id: str = "100",
    vmid: int | None = None,
    storage_id: str | None = None,
    parameters: dict[str, object] | None = None,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            node=node,
            resource_type=resource_type,
            resource_id=resource_id,
            vmid=vmid,
            storage_id=storage_id,
        ),
        parameters={} if parameters is None else parameters,
    )


def test_read_only_tool_catalog_contains_expected_domains() -> None:
    names = {spec.name for spec in READ_ONLY_TOOL_SPECS}
    permissions = {spec.permission for spec in READ_ONLY_TOOL_SPECS}

    assert "get_cluster_status" in names
    assert "list_nodes" in names
    assert "get_vm_status" in names
    assert "get_lxc_config" in names
    assert "list_storage" in names
    assert "get_firewall_rules" in names
    assert "get_ceph_status" in names
    assert "list_users" in names
    assert "monitoring.cpu.read" in permissions


def test_register_read_only_tools_adds_low_risk_proxmox_definitions() -> None:
    registry = ToolRegistry()
    register_read_only_tools(registry)

    definitions = registry.definitions()

    assert len(definitions) == len(READ_ONLY_TOOL_SPECS)
    assert all(definition.risk == "low" for definition in definitions)
    assert all(definition.connector == "proxmox_api" for definition in definitions)
    assert all(not definition.dry_run for definition in definitions)
    assert all(definition.parameters_model is not None for definition in definitions)
    assert all(definition.result_model is not None for definition in definitions)


def test_read_only_tool_schemas_are_published_per_tool() -> None:
    registry = ToolRegistry()
    register_read_only_tools(registry)

    schemas = {schema.name: schema for schema in registry.schemas()}
    vm_status_schema = schemas["get_vm_status"].parameters_schema
    list_vms_schema = schemas["list_vms"].parameters_schema

    assert vm_status_schema is not None
    assert list_vms_schema is not None
    vm_status_properties = vm_status_schema["properties"]
    list_vms_properties = list_vms_schema["properties"]
    assert isinstance(vm_status_properties, dict)
    assert isinstance(list_vms_properties, dict)
    assert "vmid" in vm_status_properties
    assert "node" in vm_status_properties
    assert "type" not in vm_status_properties
    assert "type" in list_vms_properties
    assert vm_status_schema != list_vms_schema


async def test_get_vm_status_calls_expected_proxmox_endpoint() -> None:
    registry = make_registry()
    request = make_request()
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient(
        {"/nodes/pve-1/qemu/100/status/current": {"status": "running"}}
    )

    response = await registry.execute(
        "get_vm_status", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolResponse)
    assert response.result == {"data": {"status": "running"}}
    assert client.requests[-1].path == "/nodes/pve-1/qemu/100/status/current"
    assert client.requests[-1].params == {}
    assert [event.result_status for event in writer.events] == ["started", "success"]


async def test_list_vms_adds_qemu_query_default() -> None:
    registry = make_registry()
    request = make_request(node=None, resource_type="cluster", resource_id="resources")
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient({"/cluster/resources": [{"vmid": 100}]})

    response = await registry.execute("list_vms", request, make_context(request, client, writer))

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].path == "/cluster/resources"
    assert client.requests[-1].params == {"type": "qemu"}


async def test_list_vms_rejects_type_filter_override() -> None:
    registry = make_registry()
    request = make_request(
        node=None,
        resource_type="cluster",
        resource_id="resources",
        parameters={"type": "lxc"},
    )
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient({"/cluster/resources": [{"vmid": 100}]})

    response = await registry.execute("list_vms", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "type" in response.error.message


async def test_read_only_tool_rejects_unsupported_query_parameter() -> None:
    registry = make_registry()
    request = make_request(parameters={"unexpected": "value"})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "get_vm_status", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert response.error.message == "Tool request parameters failed validation"


async def test_read_only_tool_rejects_conflicting_path_parameter() -> None:
    registry = make_registry()
    request = make_request(resource_id="100", parameters={"vmid": 101})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "get_vm_status", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "vmid" in response.error.message


async def test_read_only_tool_rejects_conflicting_target_vmid() -> None:
    registry = make_registry()
    request = make_request(resource_id="100", vmid=200)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "get_vm_status", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "vmid" in response.error.message
    assert client.requests == []


async def test_read_only_tool_rejects_conflicting_target_storage_id() -> None:
    registry = make_registry()
    request = make_request(
        resource_type="storage",
        resource_id="allowed-store",
        storage_id="secret-store",
    )
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "get_storage_content", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "storage_id" in response.error.message
    assert client.requests == []


async def test_read_only_tool_rejects_unsafe_path_segments() -> None:
    registry = make_registry()
    request = make_request(node="../pve-1")
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "get_vm_status", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "node" in response.error.message


async def test_read_only_tool_reports_missing_path_value() -> None:
    registry = make_registry()
    request = make_request(node=None)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "get_vm_status", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "node" in response.error.message


async def test_read_only_tool_reports_missing_client_as_proxmox_api_error() -> None:
    registry = make_registry()
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("get_vm_status", request, make_context(request, None, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "PROXMOX_API_ERROR"
    assert response.error.message == "Proxmox API client is not configured"


async def test_read_only_tool_sanitizes_proxmox_api_errors() -> None:
    registry = make_registry()
    request = make_request()
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "get_vm_status", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_FOUND"
    assert response.error.message == "Proxmox API request failed"
    assert response.error.retryable is False
