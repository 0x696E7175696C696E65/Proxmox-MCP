from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel, ConfigDict

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.rbac import RBACEvaluator, Role, RoleAssignment, Scope
from proxmox_mcp.rbac.capability import CapabilityRole, seed_grants_from_catalog
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition


class _EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def _noop_handler(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    _ = request, context
    return {}


def test_capability_deny_by_default() -> None:
    role = CapabilityRole(role_id="r1", name="Empty", granted_tools=frozenset())
    assert role.allows_tool("list_nodes") is False


def test_star_requires_break_glass() -> None:
    granted_tools = ["*"]
    allow_star = False
    with pytest.raises(ValueError, match="break-glass"):
        if "*" in granted_tools and not allow_star:
            raise ValueError("Granting '*' requires break-glass allow_star")


def test_capability_deny_beats_allow() -> None:
    role = CapabilityRole(
        role_id="r1",
        name="Ops",
        granted_tools=frozenset({"start_vm", "stop_vm"}),
        denied_tools=frozenset({"stop_vm"}),
    )
    assert role.allows_tool("start_vm") is True
    assert role.allows_tool("stop_vm") is False


def test_capability_star_grant() -> None:
    role = CapabilityRole(
        role_id="r1",
        name="Admin",
        granted_tools=frozenset({"*"}),
        denied_tools=frozenset({"execute_ssh"}),
    )
    assert role.allows_tool("list_nodes") is True
    assert role.allows_tool("execute_ssh") is False


def test_anti_escalation_subset() -> None:
    narrow = CapabilityRole(
        role_id="n",
        name="N",
        granted_tools=frozenset({"list_nodes"}),
    )
    broad = CapabilityRole(
        role_id="b",
        name="B",
        granted_tools=frozenset({"*"}),
    )
    assert narrow.is_subset_of(broad) is True
    assert broad.is_subset_of(narrow) is False


def test_seed_viewer_excludes_mutations() -> None:
    template = CapabilityRole(
        role_id="caprole_system_viewer",
        name="Viewer",
        base_template="viewer",
        granted_tools=frozenset(),
        system=True,
    )
    seeded = seed_grants_from_catalog(
        template,
        tool_names=["list_nodes", "start_vm", "delete_vm"],
        tool_permissions={
            "list_nodes": "node.read",
            "start_vm": "vm.lifecycle.start",
            "delete_vm": "vm.lifecycle.destroy",
        },
        tool_risks={"list_nodes": "low", "start_vm": "medium", "delete_vm": "critical"},
    )
    assert "list_nodes" in seeded.granted_tools
    assert "start_vm" not in seeded.granted_tools
    assert "delete_vm" not in seeded.granted_tools


def test_rbac_evaluator_tool_acl() -> None:
    evaluator = RBACEvaluator()
    legacy = Role.read_only()
    assert evaluator.tool_allowed(legacy, "anything") is True
    locked = Role(
        name="Custom",
        permissions=frozenset({"*"}),
        granted_tools=frozenset({"list_nodes"}),
    )
    assert evaluator.tool_allowed(locked, "list_nodes") is True
    assert evaluator.tool_allowed(locked, "start_vm") is False


@pytest.mark.asyncio
async def test_guard_tool_not_granted() -> None:
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
    request = ToolRequest(
        actor=Actor(user_id="u1", agent_id="a1"),
        target=Target(resource_type="vm", resource_id="100"),
        parameters={},
        options=RequestOptions(dry_run=True),
    )
    context = ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        authenticated_session=AuthenticatedSession(
            session_id="s1",
            identity=ActorIdentity(user_id="u1", agent_id="a1"),
            auth_method="service_token",
            status="active",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
    )
    decision = await guard.evaluate(definition, request, context)
    assert decision.decision == "denied"
    assert decision.error_code == "TOOL_NOT_GRANTED"
    assert decision.details.get("denial_reason") == "TOOL_NOT_GRANTED"
