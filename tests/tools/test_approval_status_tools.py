from __future__ import annotations

import pytest

from proxmox_mcp.approvals import InMemoryApprovalStore
from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.config import Settings
from proxmox_mcp.schemas.envelope import Actor, Target, ToolRequest
from proxmox_mcp.tools.approval_status import register_approval_status_tools
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolRegistry
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.rbac import Role, RoleAssignment, Scope
from proxmox_mcp.security import SecurityPlaneGuard
from tests.security.helpers import make_session


@pytest.mark.asyncio
async def test_approval_status_tools_are_actor_scoped(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("PROXMOX_MCP_LOG_LEVEL=info\n", encoding="utf-8")
    monkeypatch.setenv("PROXMOX_MCP_ENV_FILE", str(env_file))
    monkeypatch.setenv("PROXMOX_MCP_ENVIRONMENT", "homelab")
    monkeypatch.setenv("PROXMOX_MCP_AUTH_MODE", "service_token")
    monkeypatch.setenv("PROXMOX_MCP_SERVICE_TOKEN", "x" * 32)
    monkeypatch.setenv(
        "PROXMOX_MCP_DATABASE_URL",
        "postgresql+asyncpg://proxmox_mcp:proxmox_mcp@localhost/proxmox_mcp?ssl=require",
    )
    monkeypatch.setenv("PROXMOX_MCP_REDIS_URL", "rediss://localhost:6379/0")
    settings = Settings()

    store = InMemoryApprovalStore()
    mine = await store.queue_pending(
        operation="vm.delete",
        target=Target(resource_type="vm", resource_id="1"),
        input_payload={},
        actor=ActorIdentity(user_id="user_a", agent_id="agent_a", tenant_id=None),
        risk_level="high",
        risk_score=80,
    )
    await store.queue_pending(
        operation="vm.delete",
        target=Target(resource_type="vm", resource_id="2"),
        input_payload={},
        actor=ActorIdentity(user_id="user_b", agent_id="agent_b", tenant_id=None),
        risk_level="high",
        risk_score=80,
    )

    registry = ToolRegistry(
        guard=SecurityPlaneGuard(
            role_assignments=(
                RoleAssignment(
                    role=Role.administrator(),
                    scope=Scope(),
                    actor_user_id="user_a",
                    actor_agent_id="agent_a",
                ),
            )
        )
    )
    register_approval_status_tools(registry)

    session = make_session(
        identity=ActorIdentity(user_id="user_a", agent_id="agent_a", tenant_id=None)
    )
    request = ToolRequest(
        request_id="req-1",
        actor=Actor(user_id="user_a", agent_id="agent_a"),
        target=Target(resource_type="internal", resource_id="validation"),
        parameters={},
    )
    context = ToolExecutionContext(
        request=request,
        settings=settings,
        audit_writer=InMemoryAuditWriter(),
        approval_store=store,
        authenticated_session=session,
    )
    listed = await registry.execute("list_my_pending_approvals", request, context)
    assert listed.result["count"] == 1
    assert listed.result["approvals"][0]["approval_request_id"] == mine.approval_request_id
    assert "approval_token" not in str(listed.result)

    other = ToolRequest(
        request_id="req-2",
        actor=Actor(user_id="user_a", agent_id="agent_a"),
        target=Target(resource_type="internal", resource_id="validation"),
        parameters={"approval_request_id": "missing"},
    )
    other_ctx = ToolExecutionContext(
        request=other,
        settings=settings,
        audit_writer=InMemoryAuditWriter(),
        approval_store=store,
        authenticated_session=session,
    )
    status = await registry.execute("get_approval_status", other, other_ctx)
    assert status.result["found"] is False
