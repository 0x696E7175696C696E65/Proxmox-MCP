from __future__ import annotations

from typing import Any, cast
from uuid import uuid4

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.proxmox import register_domain_completion_tools
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig
from proxmox_mcp.rbac import RoleAssignment
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.registry import ToolRegistry

pytestmark = pytest.mark.lab


async def test_node_update_read_only_preflight_records_guarded_evidence(
    lab_config: LabEnvironmentConfig,
    lab_client: ProxmoxHttpApiClient,
    lab_read_role_assignment: RoleAssignment,
    lab_tool_context_factory: Any,
    optional_lab_node: str,
) -> None:
    registry = ToolRegistry(guard=SecurityPlaneGuard(role_assignments=(lab_read_role_assignment,)))
    register_domain_completion_tools(registry)
    request = ToolRequest(
        request_id=f"lab-{uuid4()}",
        actor=Actor(user_id="lab_user", agent_id="lab_agent", tenant_id="lab_tenant"),
        target=Target(
            tenant_id="lab_tenant",
            cluster=lab_config.cluster_id,
            node=optional_lab_node,
            resource_type="node",
            resource_id=optional_lab_node,
        ),
        parameters={"payload": {"maintenance_window": "lab-read-only"}},
        options=RequestOptions(dry_run=True),
    )

    response = await registry.execute(
        "apply_node_updates",
        request,
        lab_tool_context_factory(request, lab_client, InMemoryAuditWriter()),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    update_plan = cast(dict[str, object], result["result"])
    assert update_plan["execution_status"] == "guarded"
    assert update_plan["mutation_performed"] is False
    assert "preflight_details" in update_plan
