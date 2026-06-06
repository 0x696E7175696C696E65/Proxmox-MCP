from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    SAFE_MUTATION_TOOL_SPECS,
    InMemoryProxmoxApiClient,
    register_safe_mutation_tools,
)
from proxmox_mcp.rbac import Role, RoleAssignment, Scope
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import FastMCPRequest, ToolRegistry

RegisteredTool = Callable[[FastMCPRequest], Awaitable[ToolResponse | ToolErrorResponse]]


class RecordingFastMCP:
    def __init__(self) -> None:
        self.tools: dict[str, RegisteredTool] = {}

    def tool(self, *, name: str) -> Callable[[RegisteredTool], RegisteredTool]:
        def decorate(handler: RegisteredTool) -> RegisteredTool:
            self.tools[name] = handler
            return handler

        return decorate


def make_session() -> AuthenticatedSession:
    issued_at = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess_mutation",
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
                    role=Role(name="Operator", permissions=frozenset({"*"})),
                    scope=Scope(tenant_id="tenant_1"),
                ),
            )
        )
    )
    register_safe_mutation_tools(registry)
    return registry


def make_request(
    *,
    node: str | None = "pve-1",
    resource_type: str = "vm",
    resource_id: str = "100",
    vmid: int | None = None,
    parameters: dict[str, object] | None = None,
    dry_run: bool = True,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            node=node,
            resource_type=resource_type,
            resource_id=resource_id,
            vmid=vmid,
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


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


def test_safe_mutation_tool_metadata_supports_dry_run() -> None:
    registry = ToolRegistry()
    register_safe_mutation_tools(registry)

    definitions = registry.definitions()

    assert len(definitions) == len(SAFE_MUTATION_TOOL_SPECS)
    assert all(definition.connector == "proxmox_api" for definition in definitions)
    assert all(definition.dry_run for definition in definitions)
    assert all(definition.parameters_model is not None for definition in definitions)
    assert all(definition.result_model is not None for definition in definitions)


async def test_vm_lifecycle_dry_run_does_not_call_proxmox() -> None:
    registry = make_registry()
    request = make_request()
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("start_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolResponse)
    assert client.requests == []
    result = response.result
    assert isinstance(result, dict)
    assert result["dry_run"] is True
    assert result["endpoint"] == "/nodes/pve-1/qemu/100/status/start"
    assert result["impact"] == {
        "affected_resources": [{"type": "vm", "id": "100", "node": "pve-1"}],
        "estimated_downtime_seconds": None,
        "data_loss_possible": False,
        "rollback_available": False,
        "rollback_suggestions": [],
    }


async def test_fastmcp_mutation_defaults_omitted_options_to_dry_run() -> None:
    registry = make_registry()
    app = RecordingFastMCP()
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/qemu/100/status/start": "UPID:1"})

    def context_factory(request: ToolRequest) -> ToolExecutionContext:
        return make_context(request, client, writer)

    registry.register_with_fastmcp(app, context_factory)

    response = await app.tools["start_vm"](
        {
            "actor": {"user_id": "user_1", "agent_id": "agent_1", "tenant_id": "tenant_1"},
            "target": {
                "tenant_id": "tenant_1",
                "node": "pve-1",
                "resource_type": "vm",
                "resource_id": "100",
            },
        }
    )

    assert isinstance(response, ToolResponse)
    result = response.result
    assert isinstance(result, dict)
    assert result["dry_run"] is True
    assert client.requests == []


async def test_vm_lifecycle_live_run_calls_proxmox_post() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/qemu/100/status/start": "UPID:1"})

    response = await registry.execute("start_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].method == "POST"
    assert client.requests[-1].path == "/nodes/pve-1/qemu/100/status/start"
    result = response.result
    assert isinstance(result, dict)
    assert result["result"] == "UPID:1"


async def test_update_vm_config_live_run_calls_put_with_config_payload() -> None:
    registry = make_registry()
    request = make_request(dry_run=False, parameters={"config": {"onboot": 1}})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/qemu/100/config": "UPID:2"})

    response = await registry.execute(
        "update_vm_config",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].method == "PUT"
    assert client.requests[-1].data == {"onboot": 1}


async def test_backup_payload_includes_target_vmid_and_spec_rollback_suggestion() -> None:
    registry = make_registry()
    request = make_request(parameters={"storage": "backup-store", "mode": "snapshot"})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "run_vm_backup", request, make_context(request, client, writer)
    )

    assert isinstance(response, ToolResponse)
    result = response.result
    assert isinstance(result, dict)
    result_dict = cast(dict[str, object], result)
    assert result_dict["payload"] == {"storage": "backup-store", "mode": "snapshot", "vmid": "100"}
    impact = result_dict["impact"]
    assert isinstance(impact, dict)
    assert impact["rollback_suggestions"] == [
        "Use the completed backup as a restore point if follow-up validation fails."
    ]


async def test_snapshot_uses_spec_rollback_suggestion() -> None:
    registry = make_registry()
    request = make_request(parameters={"snapname": "before-change"})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "create_vm_snapshot",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolResponse)
    result = response.result
    assert isinstance(result, dict)
    result_dict = cast(dict[str, object], result)
    impact = result_dict["impact"]
    assert isinstance(impact, dict)
    assert impact["rollback_suggestions"] == ["Delete the created snapshot if validation fails."]


async def test_high_risk_live_mutation_requires_approval() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/qemu/100/status/shutdown": "UPID:3"})

    response = await registry.execute("shutdown_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "APPROVAL_REQUIRED"
    assert client.requests == []


async def test_snapshot_requires_name_in_schema() -> None:
    registry = make_registry()
    request = make_request(parameters={})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "create_vm_snapshot",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"


async def test_config_update_rejects_unsafe_fields() -> None:
    registry = make_registry()
    request = make_request(parameters={"config": {"args": "-device vfio-pci"}})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "update_vm_config",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "args" in response.error.message


async def test_mutation_rejects_parameter_node_without_target_node() -> None:
    registry = make_registry()
    request = make_request(node=None, parameters={"node": "pve-prod"})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("start_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_mutation_rejects_unsupported_payload_fields() -> None:
    registry = make_registry()
    request = make_request(parameters={"delete": True})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("start_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_mutation_rejects_conflicting_target_vmid() -> None:
    registry = make_registry()
    request = make_request(resource_id="100", vmid=200)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("start_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []
