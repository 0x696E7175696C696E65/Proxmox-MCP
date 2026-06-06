from __future__ import annotations

from proxmox_mcp.approvals import InMemoryApprovalStore
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.config import DangerousOperationSettings
from proxmox_mcp.schemas.envelope import ToolErrorResponse, ToolResponse
from tests.security.helpers import (
    APPROVAL_CODE,
    HandlerSpy,
    make_approval,
    make_context,
    make_registry,
    make_request,
    make_role_assignment,
    make_session,
)


async def test_missing_rbac_fails_closed_without_handler_execution() -> None:
    request = make_request()
    writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    registry = make_registry(handler)

    response = await registry.execute("delete_vm", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "RBAC_DENIED"
    assert handler.calls == 0
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_forged_request_actor_uses_authenticated_identity_in_audit() -> None:
    request = make_request(actor_user_id="user_2")
    writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    registry = make_registry(handler, role_assignments=(make_role_assignment(),))

    response = await registry.execute(
        "delete_vm",
        request,
        make_context(
            request,
            writer,
            session=make_session(
                identity=ActorIdentity(
                    user_id="user_1",
                    agent_id="agent_1",
                    tenant_id="tenant_1",
                )
            ),
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "AUTHENTICATION_FAILED"
    assert handler.calls == 0
    assert [event.actor_user_id for event in writer.events] == ["user_1", "user_1"]
    assert [event.tenant_id for event in writer.events] == ["tenant_1", "tenant_1"]


async def test_dangerous_operations_disabled_fails_before_handler_execution() -> None:
    request = make_request()
    writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    registry = make_registry(handler, role_assignments=(make_role_assignment(),))

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
    assert handler.calls == 0
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_missing_approval_fails_before_handler_execution() -> None:
    request = make_request()
    writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    registry = make_registry(handler, role_assignments=(make_role_assignment(),))

    response = await registry.execute("delete_vm", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "APPROVAL_REQUIRED"
    assert handler.calls == 0
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_valid_approval_executes_once_and_replay_fails_closed() -> None:
    request = make_request(approval_token=APPROVAL_CODE)
    writer = InMemoryAuditWriter()
    replay_writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    store = InMemoryApprovalStore((make_approval(request),))
    registry = make_registry(
        handler,
        role_assignments=(make_role_assignment(),),
        approval_store=store,
    )

    first = await registry.execute("delete_vm", request, make_context(request, writer))
    second = await registry.execute("delete_vm", request, make_context(request, replay_writer))

    assert isinstance(first, ToolResponse)
    assert first.approval.required is True
    assert handler.calls == 1
    assert [event.result_status for event in writer.events] == ["started", "success"]
    assert isinstance(second, ToolErrorResponse)
    assert second.error.code == "APPROVAL_SCOPE_MISMATCH"
    assert handler.calls == 1
    assert [event.result_status for event in replay_writer.events] == ["started", "denied"]
