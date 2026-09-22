from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from proxmox_mcp.approvals import (
    DatabaseApprovalStore,
    StoredApproval,
    canonical_json_hash,
    hash_approval_token,
)
from proxmox_mcp.persistence.database import build_session_factory
from proxmox_mcp.persistence.models import Base
from proxmox_mcp.schemas.envelope import Target, ToolErrorResponse
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.registry import ToolDefinition


@pytest.mark.asyncio
async def test_high_risk_internal_tool_requires_authz() -> None:
    from proxmox_mcp.audit.writer import InMemoryAuditWriter
    from proxmox_mcp.config import Settings
    from proxmox_mcp.schemas.envelope import Actor, RequestOptions, ToolRequest
    from proxmox_mcp.tools.context import ToolExecutionContext
    from proxmox_mcp.tools.registry import ToolRegistry

    async def handler(_request: ToolRequest, _context: ToolExecutionContext) -> dict[str, object]:
        return {"ok": True}

    registry = ToolRegistry(guard=SecurityPlaneGuard())
    registry.register(
        ToolDefinition(
            name="cancel_helper_script_execution",
            description="Cancel helper",
            category="helper",
            permission="helper.cancel",
            risk="high",
            dry_run=False,
            approval_default=True,
            connector="internal",
            handler=handler,
        )
    )
    request = ToolRequest(
        actor=Actor(user_id="u", agent_id="a"),
        target=Target(resource_type="cluster", resource_id="lab"),
        options=RequestOptions(dry_run=False),
    )
    writer = InMemoryAuditWriter()
    response = await registry.execute(
        "cancel_helper_script_execution",
        request,
        ToolExecutionContext(
            request=request,
            settings=Settings(environment="test"),
            audit_writer=writer,
        ),
    )
    assert isinstance(response, ToolErrorResponse)
    assert response.error.code in {
        "AUTHENTICATION_REQUIRED",
        "AUTHENTICATION_FAILED",
        "RBAC_DENIED",
    }


@pytest.mark.asyncio
async def test_health_check_internal_still_allowed() -> None:
    from proxmox_mcp.audit.writer import InMemoryAuditWriter
    from proxmox_mcp.config import Settings
    from proxmox_mcp.schemas.envelope import Actor, RequestOptions, ToolRequest, ToolResponse
    from proxmox_mcp.tools.context import ToolExecutionContext
    from proxmox_mcp.tools.internal import HEALTH_CHECK_DEFINITION
    from proxmox_mcp.tools.registry import ToolRegistry

    registry = ToolRegistry(guard=SecurityPlaneGuard())
    registry.register(HEALTH_CHECK_DEFINITION)
    request = ToolRequest(
        actor=Actor(user_id="system", agent_id="system"),
        target=Target(resource_type="internal", resource_id="health"),
        options=RequestOptions(dry_run=True),
    )
    writer = InMemoryAuditWriter()
    response = await registry.execute(
        "health_check",
        request,
        ToolExecutionContext(
            request=request,
            settings=Settings(environment="test"),
            audit_writer=writer,
        ),
    )
    assert isinstance(response, ToolResponse)
    assert response.status == "success"


@pytest.mark.asyncio
async def test_approval_decide_is_single_transition(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'apr.db').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    store = DatabaseApprovalStore(build_session_factory(engine))
    now = datetime(2026, 1, 1, tzinfo=UTC)
    target = Target(resource_type="vm", resource_id="100")
    approval = StoredApproval(
        approval_request_id="apr_decide_1",
        operation="delete_vm",
        target_hash=canonical_json_hash(target.model_dump(mode="json")),
        input_hash=canonical_json_hash({"force": True}),
        approval_token_hash=hash_approval_token("tok"),
        actor_user_id="user_1",
        actor_agent_id="agent_1",
        actor_tenant_id="tenant_1",
        risk_level="critical",
        risk_score=95,
        expires_at=now + timedelta(minutes=5),
        status="pending",
    )
    await store.add(approval)
    first = await store.decide("apr_decide_1", decision="approved", decided_by="admin", reason="ok")
    second = await store.decide("apr_decide_1", decision="rejected", decided_by="admin", reason="no")
    await engine.dispose()
    assert first is not None
    assert first["status"] == "approved"
    assert first["decided_by"] == "admin"
    assert second is None
