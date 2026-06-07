from __future__ import annotations

from typing import Protocol, cast

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.reliability import ProxmoxTaskStore
from proxmox_mcp.schemas.envelope import Actor, Target, ToolErrorResponse, ToolRequest, ToolResponse
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolRegistry

pytestmark = pytest.mark.lab


class ContextFactory(Protocol):
    def __call__(
        self,
        request: ToolRequest,
        lab_client: ProxmoxHttpApiClient,
        audit_writer: InMemoryAuditWriter,
        *,
        authenticated: bool = True,
        proxmox_task_store: ProxmoxTaskStore | None = None,
    ) -> ToolExecutionContext: ...


async def test_registered_read_tool_executes_through_security_and_audit(
    lab_read_tool_registry: ToolRegistry,
    lab_tool_context_factory: ContextFactory,
    lab_client: ProxmoxHttpApiClient,
    lab_audit_writer: InMemoryAuditWriter,
) -> None:
    request = _list_nodes_request()

    response = await lab_read_tool_registry.execute(
        "list_nodes",
        request,
        lab_tool_context_factory(request, lab_client, lab_audit_writer),
    )

    assert isinstance(response, ToolResponse)
    raw_result: object = response.result
    assert isinstance(raw_result, dict)
    result = cast(dict[str, object], raw_result)
    assert isinstance(result["data"], list)
    assert [event.result_status for event in lab_audit_writer.events] == ["started", "success"]
    assert {event.tool_name for event in lab_audit_writer.events} == {"list_nodes"}
    assert {event.actor_user_id for event in lab_audit_writer.events} == {"lab_user"}


async def test_registered_read_tool_requires_authenticated_lab_session(
    lab_read_tool_registry: ToolRegistry,
    lab_tool_context_factory: ContextFactory,
    lab_client: ProxmoxHttpApiClient,
    lab_audit_writer: InMemoryAuditWriter,
) -> None:
    request = _list_nodes_request()

    response = await lab_read_tool_registry.execute(
        "list_nodes",
        request,
        lab_tool_context_factory(
            request,
            lab_client,
            lab_audit_writer,
            authenticated=False,
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "AUTHENTICATION_REQUIRED"


async def test_registered_read_tool_enforces_rbac_before_lab_api_call(
    lab_unauthorized_read_tool_registry: ToolRegistry,
    lab_tool_context_factory: ContextFactory,
    lab_client: ProxmoxHttpApiClient,
    lab_audit_writer: InMemoryAuditWriter,
) -> None:
    request = _list_nodes_request()

    response = await lab_unauthorized_read_tool_registry.execute(
        "list_nodes",
        request,
        lab_tool_context_factory(request, lab_client, lab_audit_writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "RBAC_DENIED"


async def test_registered_read_tool_enforces_policy_before_lab_api_call(
    lab_policy_denied_read_tool_registry: ToolRegistry,
    lab_tool_context_factory: ContextFactory,
    lab_client: ProxmoxHttpApiClient,
    lab_audit_writer: InMemoryAuditWriter,
) -> None:
    request = _list_nodes_request()

    response = await lab_policy_denied_read_tool_registry.execute(
        "list_nodes",
        request,
        lab_tool_context_factory(request, lab_client, lab_audit_writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "POLICY_DENIED"


def _list_nodes_request() -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="lab_user", agent_id="lab_agent", tenant_id="lab_tenant"),
        target=Target(
            tenant_id="lab_tenant",
            cluster="lab",
            resource_type="cluster",
            resource_id="nodes",
        ),
        parameters={},
    )
