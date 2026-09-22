from __future__ import annotations

from pathlib import Path
from typing import cast

from sqlalchemy.ext.asyncio import create_async_engine

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.persistence.database import build_session_factory
from proxmox_mcp.persistence.models import Base
from proxmox_mcp.proxmox import InMemoryProxmoxApiClient, register_safe_mutation_tools
from proxmox_mcp.reliability import DatabaseProxmoxTaskStore
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
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


def _session() -> AuthenticatedSession:
    from datetime import UTC, datetime, timedelta

    issued_at = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess-task",
        identity=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        auth_method="service_token",
        status="active",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=15),
    )


async def test_mutating_proxmox_operation_persists_upid_task_state(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'tasks.db').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    task_store = DatabaseProxmoxTaskStore(build_session_factory(engine))
    registry = ToolRegistry(guard=AllowGuard())
    register_safe_mutation_tools(registry)
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            node="pve-1",
            resource_type="vm",
            resource_id="100",
        ),
        parameters={},
        options=RequestOptions(dry_run=False, idempotency_key="start-vm-100"),
    )
    client = InMemoryProxmoxApiClient(
        {"/nodes/pve-1/qemu/100/status/start": "UPID:pve-1:0001:0002:start_vm:100:user@pam:"}
    )

    response = await registry.execute(
        "start_vm",
        request,
        ToolExecutionContext(
            request=request,
            settings=Settings(environment="test"),
            audit_writer=InMemoryAuditWriter(),
            authenticated_session=_session(),
            proxmox_client=client,
            proxmox_task_store=task_store,
        ),
    )
    stored = await task_store.get_by_upid("UPID:pve-1:0001:0002:start_vm:100:user@pam:")
    await engine.dispose()

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["task_ref"] == stored.task_id
    assert stored.operation == "start_vm"
    assert stored.idempotency_key == "start-vm-100"
    assert stored.status == "running"
