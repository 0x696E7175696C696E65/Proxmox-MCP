from __future__ import annotations

from collections.abc import Awaitable, Callable
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
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolRegistry

APPROVAL_CODE = "approved-request-code"

type Handler = Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]


class HandlerSpy:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(
        self,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> dict[str, object]:
        self.calls += 1
        return {"resource_id": request.target.resource_id, "request_id": context.request_id}


def make_request(
    *,
    approval_token: str | None = None,
    actor_user_id: str = "user_1",
    actor_agent_id: str = "agent_1",
    actor_tenant_id: str = "tenant_1",
    target_tenant_id: str = "tenant_1",
    resource_id: str = "100",
    parameters: dict[str, object] | None = None,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(
            user_id=actor_user_id,
            agent_id=actor_agent_id,
            tenant_id=actor_tenant_id,
        ),
        target=Target(
            tenant_id=target_tenant_id,
            cluster="prod",
            node="pve-1",
            resource_type="vm",
            resource_id=resource_id,
        ),
        parameters={"force": True} if parameters is None else parameters,
        options=RequestOptions(approval_token=approval_token),
    )


def make_session(
    *,
    identity: ActorIdentity | None = None,
    status: SessionStatus = "active",
) -> AuthenticatedSession:
    issued_at = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess_1",
        identity=identity
        if identity is not None
        else ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        auth_method="service_token",
        status=status,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=15),
    )


def make_context(
    request: ToolRequest,
    writer: InMemoryAuditWriter,
    *,
    dangerous_operations: DangerousOperationSettings | None = None,
    session: AuthenticatedSession | None = None,
    audit_metadata: dict[str, object] | None = None,
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
        audit_metadata={} if audit_metadata is None else audit_metadata,
    )


def make_delete_definition(handler: Handler) -> ToolDefinition:
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


def make_approval(request: ToolRequest, *, token: str = APPROVAL_CODE) -> StoredApproval:
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


def make_registry(
    handler: Handler,
    *,
    role_assignments: tuple[RoleAssignment, ...] = (),
    approval_store: InMemoryApprovalStore | None = None,
) -> ToolRegistry:
    registry = ToolRegistry(
        guard=SecurityPlaneGuard(
            role_assignments=role_assignments,
            approval_store=approval_store,
        )
    )
    registry.register(make_delete_definition(handler))
    return registry
