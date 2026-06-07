from __future__ import annotations

from typing import cast
from uuid import uuid4

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import register_domain_completion_tools
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig
from proxmox_mcp.rbac import RoleAssignment
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolRegistry

pytestmark = pytest.mark.lab


async def test_storage_benchmark_preview_records_cleanup_evidence(
    lab_config: LabEnvironmentConfig,
    lab_read_role_assignment: RoleAssignment,
    optional_lab_node: str,
    optional_lab_storage: str,
) -> None:
    if lab_config.profile != "pve-9-storage-local-local-lvm":
        pytest.skip(
            "Select PROXMOX_MCP_LAB_PROFILE=pve-9-storage-local-local-lvm "
            "for storage promotion gates"
        )

    registry = ToolRegistry(guard=SecurityPlaneGuard(role_assignments=(lab_read_role_assignment,)))
    register_domain_completion_tools(registry)
    request = ToolRequest(
        request_id=f"lab-{uuid4()}",
        actor=Actor(user_id="lab_user", agent_id="lab_agent", tenant_id="lab_tenant"),
        target=Target(
            tenant_id="lab_tenant",
            cluster=lab_config.cluster_id,
            node=optional_lab_node,
            resource_type="storage",
            resource_id=optional_lab_storage,
            storage_id=optional_lab_storage,
        ),
        parameters={
            "payload": {
                "backend": "dir",
                "target_type": "storage",
                "duration_seconds": 5,
                "max_bytes": 4096,
            }
        },
        options=RequestOptions(dry_run=True),
    )

    response = await registry.execute(
        "benchmark_storage",
        request,
        ToolExecutionContext(
            request=request,
            settings=Settings(environment="test"),
            audit_writer=InMemoryAuditWriter(),
        ),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    benchmark_plan = cast(dict[str, object], result["result"])
    assert benchmark_plan["execution_status"] == "bounded_live_supported"
    assert benchmark_plan["artifact_path"] == (
        f"/var/lib/vz/mcp-lab-{optional_lab_storage}-benchmark.dat"
    )
    assert benchmark_plan["cleanup_required"] is True


async def test_storage_expansion_remains_backend_guarded(
    lab_config: LabEnvironmentConfig,
    lab_read_role_assignment: RoleAssignment,
    optional_lab_node: str,
    optional_lab_storage: str,
) -> None:
    if lab_config.profile != "pve-9-storage-local-local-lvm":
        pytest.skip(
            "Select PROXMOX_MCP_LAB_PROFILE=pve-9-storage-local-local-lvm "
            "for storage promotion gates"
        )

    registry = ToolRegistry(guard=SecurityPlaneGuard(role_assignments=(lab_read_role_assignment,)))
    register_domain_completion_tools(registry)
    request = ToolRequest(
        request_id=f"lab-{uuid4()}",
        actor=Actor(user_id="lab_user", agent_id="lab_agent", tenant_id="lab_tenant"),
        target=Target(
            tenant_id="lab_tenant",
            cluster=lab_config.cluster_id,
            node=optional_lab_node,
            resource_type="storage",
            resource_id=optional_lab_storage,
            storage_id=optional_lab_storage,
        ),
        parameters={"payload": {"backend": "lvmthin", "requested_size": "+1G"}},
        options=RequestOptions(dry_run=True),
    )

    response = await registry.execute(
        "expand_storage",
        request,
        ToolExecutionContext(
            request=request,
            settings=Settings(environment="test"),
            audit_writer=InMemoryAuditWriter(),
        ),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    expansion_plan = cast(dict[str, object], result["result"])
    assert expansion_plan["execution_status"] == "guarded"
