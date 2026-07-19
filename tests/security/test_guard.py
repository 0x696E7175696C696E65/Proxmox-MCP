from __future__ import annotations

from datetime import UTC, datetime, timedelta

from proxmox_mcp.approvals import (
    InMemoryApprovalStore,
    StoredApproval,
    canonical_json_hash,
    hash_approval_token,
)
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession, SessionStatus
from proxmox_mcp.config import DangerousOperationSettings, Settings
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
from proxmox_mcp.tools.registry import ToolDefinition, ToolRegistry

APPROVAL_CODE = "approved-request-code"


async def handler(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    return {"resource_id": request.target.resource_id, "request_id": context.request_id}


def make_request(*, approval_token: str | None = None) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            cluster="prod",
            node="pve-1",
            resource_type="vm",
            resource_id="100",
        ),
        parameters={"force": True},
        options=RequestOptions(approval_token=approval_token),
    )


def make_context(
    request: ToolRequest,
    writer: InMemoryAuditWriter,
    *,
    dangerous_operations: DangerousOperationSettings | None = None,
    session: AuthenticatedSession | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(
            environment="test",
            dangerous_operations=DangerousOperationSettings()
            if dangerous_operations is None
            else dangerous_operations,
        ),
        audit_writer=writer,
        authenticated_session=make_session() if session is None else session,
    )


def make_session(
    *,
    identity: ActorIdentity | None = None,
    status: SessionStatus = "active",
) -> AuthenticatedSession:
    issued_at = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess_1",
        identity=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1")
        if identity is None
        else identity,
        auth_method="service_token",
        status=status,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=15),
    )


def make_delete_definition() -> ToolDefinition:
    return ToolDefinition(
        name="delete_vm",
        description="Delete a VM (test definition).",
        category="vm",
        permission="vm.delete",
        risk="high",
        dry_run=False,
        approval_default=True,
        connector="proxmox_api",
        handler=handler,
    )


def make_role_assignment() -> RoleAssignment:
    return RoleAssignment(
        actor_user_id="user_1",
        actor_agent_id="agent_1",
        role=Role(name="VM Deleter", permissions=frozenset({"vm.delete"})),
        scope=Scope(tenant_id="tenant_1", resource_type="vm"),
    )


def make_approval(request: ToolRequest, *, token: str | None = None) -> StoredApproval:
    token = APPROVAL_CODE if token is None else token
    return StoredApproval(
        approval_request_id="apr_1",
        operation="vm.delete",
        target_hash=canonical_json_hash(request.target.model_dump(mode="json")),
        input_hash=canonical_json_hash(request.parameters),
        approval_token_hash=hash_approval_token(token),
        actor_user_id=request.actor.user_id,
        actor_agent_id=request.actor.agent_id,
        actor_tenant_id=request.actor.tenant_id,
        risk_level="critical",
        risk_score=95,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        status="approved",
    )


async def test_security_guard_denies_without_matching_rbac_assignment() -> None:
    registry = ToolRegistry(guard=SecurityPlaneGuard())
    registry.register(make_delete_definition())
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("delete_vm", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "RBAC_DENIED"
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_security_guard_rejects_forged_request_actor() -> None:
    guard = SecurityPlaneGuard(role_assignments=(make_role_assignment(),))
    registry = ToolRegistry(guard=guard)
    registry.register(make_delete_definition())
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute(
        "delete_vm",
        request,
        make_context(
            request,
            writer,
            session=make_session(
                identity=ActorIdentity(
                    user_id="user_2",
                    agent_id="agent_1",
                    tenant_id="tenant_1",
                )
            ),
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "AUTHENTICATION_FAILED"
    assert [event.actor_user_id for event in writer.events] == ["user_2", "user_2"]
    assert [event.tenant_id for event in writer.events] == ["tenant_1", "tenant_1"]


async def test_security_guard_blocks_dangerous_operations_when_disabled() -> None:
    guard = SecurityPlaneGuard(role_assignments=(make_role_assignment(),))
    registry = ToolRegistry(guard=guard)
    registry.register(make_delete_definition())
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute(
        "delete_vm",
        request,
        make_context(
            request,
            writer,
            dangerous_operations=DangerousOperationSettings(enabled=False),
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "DANGEROUS_OPERATION_DISABLED"
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_security_guard_requires_approval_without_executing_handler() -> None:
    guard = SecurityPlaneGuard(role_assignments=(make_role_assignment(),))
    registry = ToolRegistry(guard=guard)
    registry.register(make_delete_definition())
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("delete_vm", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "APPROVAL_REQUIRED"
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_security_guard_consumes_approval_token_once() -> None:
    request = make_request(approval_token=APPROVAL_CODE)
    store = InMemoryApprovalStore((make_approval(request),))
    guard = SecurityPlaneGuard(
        role_assignments=(make_role_assignment(),),
        approval_store=store,
    )
    registry = ToolRegistry(guard=guard)
    registry.register(make_delete_definition())
    first_writer = InMemoryAuditWriter()
    second_writer = InMemoryAuditWriter()

    first = await registry.execute("delete_vm", request, make_context(request, first_writer))
    second = await registry.execute("delete_vm", request, make_context(request, second_writer))

    assert isinstance(first, ToolResponse)
    assert first.risk.dangerous_operation is True
    assert first.approval.required is True
    assert isinstance(second, ToolErrorResponse)
    assert second.error.code == "APPROVAL_SCOPE_MISMATCH"
