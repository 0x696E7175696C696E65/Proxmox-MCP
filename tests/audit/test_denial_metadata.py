from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel, ConfigDict

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.rbac import Role, RoleAssignment, Scope
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolRegistry


class _EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def _noop_handler(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    _ = request, context
    return {}


@pytest.mark.asyncio
async def test_denied_invoke_writes_tool_not_granted_metadata() -> None:
    role = Role(
        name="Locked",
        permissions=frozenset({"*"}),
        granted_tools=frozenset({"list_nodes"}),
    )
    guard = SecurityPlaneGuard(
        role_assignments=(
            RoleAssignment(
                role=role,
                scope=Scope(),
                actor_user_id="u1",
                actor_agent_id="a1",
            ),
        )
    )
    writer = InMemoryAuditWriter()
    registry = ToolRegistry(guard=guard)
    definition = ToolDefinition(
        name="start_vm",
        description="start",
        category="vm",
        permission="vm.lifecycle.start",
        risk="medium",
        dry_run=True,
        approval_default=False,
        connector="proxmox_api",
        parameters_model=_EmptyParams,
        handler=_noop_handler,
    )
    registry.register(definition)
    request = ToolRequest(
        actor=Actor(user_id="u1", agent_id="a1"),
        target=Target(resource_type="vm", resource_id="100"),
        parameters={},
        options=RequestOptions(dry_run=True),
    )
    context = ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=writer,
        authenticated_session=AuthenticatedSession(
            session_id="s1",
            identity=ActorIdentity(user_id="u1", agent_id="a1"),
            auth_method="service_token",
            status="active",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
    )
    response = await registry.execute(definition.name, request, context)
    assert isinstance(response, object)
    assert getattr(response, "error").code == "TOOL_NOT_GRANTED"  # type: ignore[union-attr]
    events = writer.events
    finished = [e for e in events if e.result_status == "denied"]
    assert finished
    meta = finished[-1].metadata
    assert meta.get("denial_reason") == "TOOL_NOT_GRANTED"
    assert meta.get("matched_rule") == "start_vm"
    assert meta.get("risk_level") == "medium"
    assert "duration_ms" in meta
