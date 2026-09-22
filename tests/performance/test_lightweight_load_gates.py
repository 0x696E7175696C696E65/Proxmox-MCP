from __future__ import annotations

from time import perf_counter

from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.observability import InMemoryMetricsRegistry
from proxmox_mcp.policy import PolicyDecision, PolicyEngine, PolicyRule, PolicyTarget
from proxmox_mcp.rbac import AccessTarget, RBACEvaluator, Role, RoleAssignment, Scope


def test_metrics_registry_renders_large_inventory_without_quadratic_growth() -> None:
    registry = InMemoryMetricsRegistry()
    for index in range(1_000):
        registry.record_tool_invocation(
            tool_name=f"tool_{index % 10}",
            connector="proxmox_api",
            status="success",
            duration_ms=index % 250,
        )

    started_at = perf_counter()
    rendered = registry.render_prometheus()
    elapsed_seconds = perf_counter() - started_at

    assert "proxmox_mcp_tool_invocations_total" in rendered
    assert "proxmox_mcp_tool_invocation_duration_ms" in rendered
    assert elapsed_seconds < 2.0


def test_policy_and_rbac_evaluation_stays_lightweight_for_common_request_path() -> None:
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1")
    access_target = AccessTarget(
        tenant_id="tenant_1",
        cluster="lab",
        node="pve-1",
        resource_type="vm",
        resource_id="100",
    )
    policy_target = PolicyTarget(
        tenant_id="tenant_1",
        cluster="lab",
        node="pve-1",
        resource_type="vm",
        resource_id="100",
    )
    assignments = (
        RoleAssignment(
            actor_user_id="user_1",
            role=Role(name="VmAdmin", permissions=frozenset({"vm.lifecycle.*"})),
            scope=Scope(tenant_id="tenant_1", resource_type="vm"),
        ),
    )
    rbac = RBACEvaluator()
    policy = PolicyEngine(
        rules=(
            PolicyRule(
                rule_id="allow-vm-start",
                effect="allow",
                operations=("vm.lifecycle.start",),
                resource_type="vm",
            ),
        )
    )

    started_at = perf_counter()
    for _ in range(1_000):
        assert rbac.is_allowed(actor, "vm.lifecycle.start", access_target, assignments)
        assert policy.evaluate("vm.lifecycle.start", policy_target) == PolicyDecision(
            decision="allowed",
            matched_rules=["allow-vm-start"],
        )
    elapsed_seconds = perf_counter() - started_at

    assert elapsed_seconds < 2.0
