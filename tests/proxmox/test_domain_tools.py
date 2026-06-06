from __future__ import annotations

from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    InMemoryProxmoxApiClient,
    domain_tool_promotion_records,
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


class WriteOnlyAuditWriter:
    async def write(self, event: object) -> None:
        _ = event


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
        ssh_command_policy=SshCommandPolicy(allowed_executables=frozenset({"zpool", "pvesh"})),
    )


def make_write_only_audit_context(request: ToolRequest) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=WriteOnlyAuditWriter(),
    )


async def test_domain_tool_dry_run_returns_endpoint_and_payload_without_calling_api() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"name": "vm-100"}})
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "create_vm",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolResponse)
    assert client.requests == []
    result = cast(dict[str, object], response.result)
    assert result["endpoint"] == "/nodes/pve-1/qemu"
    assert result["payload"] == {"name": "vm-100"}
    assert result["risk"] == "high"
    assert result["live_supported"] is True
    assert result["promotion_status"] == "live_supported"
    assert isinstance(result["impact"], dict)
    assert (
        result["rollback_guidance"] == "Verify target state and rollback path before live execution"
    )


async def test_domain_tool_live_run_calls_proxmox_api() -> None:
    registry = make_registry()
    request = make_request(
        parameters={"service": "pvedaemon", "payload": {"state": "started"}},
        dry_run=False,
    )
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/services/pvedaemon/state": "UPID:service"})

    response = await registry.execute(
        "start_node_service",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].method == "POST"
    assert client.requests[-1].path == "/nodes/pve-1/services/pvedaemon/state"


async def test_domain_ssh_tool_executes_command() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemorySshClient(
        command_results={
            "zpool status -x": SshCommandResult(exit_status=0, stdout="all pools healthy")
        }
    )

    response = await registry.execute(
        "get_zfs_health",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    command_result = cast(dict[str, object], result["result"])
    assert command_result["stdout"] == "all pools healthy"


async def test_live_placeholder_mutation_returns_not_implemented() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemorySshClient()

    response = await registry.execute(
        "expand_storage",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
    assert client.executions == []


async def test_enter_lxc_console_dry_run_previews_console_command() -> None:
    registry = make_registry()
    request = make_request()
    client = InMemorySshClient()

    response = await registry.execute(
        "enter_lxc_console",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["command"] == "pct enter 100"
    assert result["promotion_status"] == "guarded_not_implemented"
    assert client.executions == []


async def test_target_backed_parameters_must_match_authorized_target() -> None:
    registry = make_registry()
    request = make_request(parameters={"vmid": 200}, dry_run=False)
    client = InMemorySshClient()

    response = await registry.execute(
        "enter_lxc_console",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.executions == []


async def test_target_metadata_must_match_resource_id() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    request.target.vmid = 200
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "reset_vm",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_unsupported_dry_run_does_not_advertise_placeholder_command() -> None:
    registry = make_registry()
    request = make_request()

    response = await registry.execute(
        "expand_storage",
        request,
        make_context(request),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["command"] is None


async def test_missing_endpoint_parameter_is_rejected() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "delete_bridge",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_unsafe_endpoint_parameter_is_rejected() -> None:
    registry = make_registry()
    request = make_request(parameters={"iface": "../vmbr0"}, dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "delete_bridge",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


def test_domain_tool_schema_is_scoped_to_template_fields() -> None:
    registry = make_registry()
    schemas = {schema.name: schema.parameters_schema for schema in registry.schemas()}
    create_vm_schema = schemas["create_vm"]
    delete_bridge_schema = schemas["delete_bridge"]

    assert create_vm_schema is not None
    assert delete_bridge_schema is not None
    create_vm_properties = cast(dict[str, object], create_vm_schema["properties"])
    delete_bridge_properties = cast(dict[str, object], delete_bridge_schema["properties"])
    delete_bridge_required = cast(list[str], delete_bridge_schema["required"])
    assert "service" not in create_vm_properties
    assert "iface" in delete_bridge_properties
    assert "iface" in delete_bridge_required
    iface_schema = cast(dict[str, object], delete_bridge_properties["iface"])
    assert iface_schema["type"] == "string"


def test_domain_tool_schema_uses_concrete_union_for_vmid() -> None:
    registry = make_registry()
    schemas = {schema.name: schema.parameters_schema for schema in registry.schemas()}
    reset_vm_schema = schemas["reset_vm"]

    assert reset_vm_schema is not None
    properties = cast(dict[str, object], reset_vm_schema["properties"])
    vmid_schema = cast(dict[str, object], properties["vmid"])
    variants = cast(list[dict[str, object]], vmid_schema["anyOf"])
    assert {"type": "integer"} in variants
    assert {"type": "string"} in variants


def test_domain_promotion_records_define_replacement_criteria() -> None:
    records = {record.name: record for record in domain_tool_promotion_records()}

    assert set(records) >= {"create_vm", "create_zfs_pool", "expand_storage", "get_audit_events"}
    create_vm = records["create_vm"]
    assert create_vm.endpoint_template == "/nodes/{node}/qemu"
    assert create_vm.method == "POST"
    assert create_vm.path_fields == ("node",)
    assert create_vm.payload_field == "payload"
    assert create_vm.live_supported is True
    assert create_vm.lab_validation_required is True

    create_zfs_pool = records["create_zfs_pool"]
    assert create_zfs_pool.live_supported is True
    assert create_zfs_pool.promotion_status == "live_supported"
    assert create_zfs_pool.command_template == "zpool create {pool} {device}"

    expand_storage = records["expand_storage"]
    assert expand_storage.live_supported is False
    assert expand_storage.promotion_status == "guarded_not_implemented"
    assert "NOT_IMPLEMENTED" in expand_storage.failure_semantics

    get_audit_events = records["get_audit_events"]
    assert get_audit_events.promotion_status == "live_supported"
    assert get_audit_events.lab_validation_required is False


async def test_get_audit_events_requires_queryable_repository() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)

    response = await registry.execute(
        "get_audit_events",
        request,
        make_write_only_audit_context(request),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
