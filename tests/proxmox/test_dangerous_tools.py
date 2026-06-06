from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    DANGEROUS_TOOL_SPECS,
    InMemoryProxmoxApiClient,
    register_dangerous_tools,
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
from proxmox_mcp.tools.registry import (
    FastMCPRequest,
    ToolDefinition,
    ToolExecutionGuard,
    ToolGuardDecision,
    ToolRegistry,
)

RegisteredTool = Callable[[FastMCPRequest], Awaitable[ToolResponse | ToolErrorResponse]]


class AllowGuard:
    async def evaluate(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolGuardDecision:
        _ = definition, request, context
        return ToolGuardDecision.allowed()


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
        session_id="sess_dangerous",
        identity=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        auth_method="service_token",
        status="active",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=15),
    )


def make_registry(*, guard: ToolExecutionGuard | None = None) -> ToolRegistry:
    registry = ToolRegistry(guard=AllowGuard() if guard is None else guard)
    register_dangerous_tools(registry)
    return registry


def make_security_guard() -> SecurityPlaneGuard:
    return SecurityPlaneGuard(
        role_assignments=(
            RoleAssignment(
                actor_user_id="user_1",
                actor_agent_id="agent_1",
                role=Role(name="ClusterAdmin", permissions=frozenset({"*"})),
                scope=Scope(tenant_id="tenant_1"),
            ),
        )
    )


def make_request(
    *,
    node: str | None = "pve-1",
    resource_type: str = "vm",
    resource_id: str = "100",
    vmid: int | None = None,
    storage_id: str | None = None,
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
            storage_id=storage_id,
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


def test_dangerous_tool_metadata_requires_dry_run_and_approval() -> None:
    registry = ToolRegistry()
    register_dangerous_tools(registry)

    definitions = registry.definitions()

    assert len(definitions) == len(DANGEROUS_TOOL_SPECS)
    assert all(definition.connector == "proxmox_api" for definition in definitions)
    assert {definition.risk for definition in definitions} <= {"high", "critical"}
    assert all(definition.dry_run for definition in definitions)
    assert all(definition.approval_default for definition in definitions)


async def test_delete_vm_dry_run_returns_critical_impact_without_calling_proxmox() -> None:
    registry = make_registry()
    request = make_request()
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("delete_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolResponse)
    assert client.requests == []
    result = cast(dict[str, object], response.result)
    assert result["dry_run"] is True
    assert result["endpoint"] == "/nodes/pve-1/qemu/100"
    impact = cast(dict[str, object], result["impact"])
    assert impact["data_loss_possible"] is True
    assert impact["rollback_suggestions"] == [
        "Restore from a verified backup if deletion was unintended."
    ]


async def test_live_dangerous_operation_requires_approval_before_handler() -> None:
    registry = make_registry(guard=make_security_guard())
    request = make_request(dry_run=False)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient(
        {
            "/nodes/pve-1/qemu/100/status/current": {"status": "stopped"},
            "/nodes/pve-1/qemu/100": "UPID:delete",
        }
    )

    response = await registry.execute("delete_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "APPROVAL_REQUIRED"
    assert client.requests == []


async def test_live_delete_vm_revalidates_target_before_delete() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient(
        {
            "/nodes/pve-1/qemu/100/status/current": {"status": "stopped"},
            "/nodes/pve-1/qemu/100": "UPID:delete",
        }
    )

    response = await registry.execute("delete_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolResponse)
    assert [(call.method, call.path) for call in client.requests] == [
        ("GET", "/nodes/pve-1/qemu/100/status/current"),
        ("DELETE", "/nodes/pve-1/qemu/100"),
    ]
    result = cast(dict[str, object], response.result)
    assert result["target_revalidated"] is True
    assert writer.events[-1].metadata["target_revalidated"] is True


async def test_revalidation_failure_blocks_destructive_call() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/qemu/100": "UPID:delete"})

    response = await registry.execute("delete_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_FOUND"
    assert [(call.method, call.path) for call in client.requests] == [
        ("GET", "/nodes/pve-1/qemu/100/status/current")
    ]


async def test_snapshot_delete_requires_snapshot_name() -> None:
    registry = make_registry()
    request = make_request(parameters={})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "delete_vm_snapshot",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"


async def test_snapshot_delete_rejects_unsafe_path_parameter() -> None:
    registry = make_registry()
    request = make_request(parameters={"snapname": "../escape"})
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "delete_vm_snapshot",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_path_only_parameters_are_not_forwarded_in_payload() -> None:
    registry = make_registry()
    request = make_request(parameters={"snapname": "before-change"}, dry_run=False)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient(
        {
            "/nodes/pve-1/qemu/100/snapshot": [{"name": "before-change"}],
            "/nodes/pve-1/qemu/100/snapshot/before-change": "UPID:snapshot-delete",
        }
    )

    response = await registry.execute(
        "delete_vm_snapshot",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolResponse)
    assert [(call.method, call.path, call.data) for call in client.requests] == [
        ("GET", "/nodes/pve-1/qemu/100/snapshot", {}),
        ("DELETE", "/nodes/pve-1/qemu/100/snapshot/before-change", {}),
    ]


async def test_disable_firewall_uses_declared_payload_and_network_impact() -> None:
    registry = make_registry()
    request = make_request(resource_type="firewall", resource_id="cluster", dry_run=False)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient(
        {
            "/cluster/firewall/options": {"enable": 1},
        }
    )

    response = await registry.execute(
        "disable_firewall",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolResponse)
    assert [(call.method, call.path, call.data) for call in client.requests] == [
        ("GET", "/cluster/firewall/options", {}),
        ("PUT", "/cluster/firewall/options", {"enable": 0}),
    ]
    result = cast(dict[str, object], response.result)
    impact = cast(dict[str, object], result["impact"])
    assert impact["network_disruption_possible"] is True


async def test_fastmcp_dangerous_tool_defaults_omitted_options_to_dry_run() -> None:
    registry = make_registry()
    app = RecordingFastMCP()
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/qemu/100": "UPID:delete"})

    def context_factory(request: ToolRequest) -> ToolExecutionContext:
        return make_context(request, client, writer)

    registry.register_with_fastmcp(app, context_factory)

    response = await app.tools["delete_vm"](
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
    assert client.requests == []
    result = cast(dict[str, object], response.result)
    assert result["dry_run"] is True


async def test_dangerous_tool_rejects_conflicting_target_vmid() -> None:
    registry = make_registry()
    request = make_request(resource_id="100", vmid=200)
    writer = InMemoryAuditWriter()
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("delete_vm", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []
