from __future__ import annotations

from proxmox_mcp.policy import PolicyEngine, PolicyRule, PolicyTarget


def test_policy_deny_takes_precedence_over_allow() -> None:
    engine = PolicyEngine(
        rules=(
            PolicyRule(
                rule_id="allow-start",
                effect="allow",
                operations=("vm.lifecycle.start",),
                priority=100,
            ),
            PolicyRule(
                rule_id="deny-start",
                effect="deny",
                operations=("vm.lifecycle.start",),
                priority=1,
            ),
        )
    )

    decision = engine.evaluate(
        "vm.lifecycle.start",
        PolicyTarget(tenant_id="tenant_1", resource_type="vm", resource_id="100"),
    )

    assert decision.decision == "denied"
    assert decision.matched_rules == ["allow-start", "deny-start"]


def test_policy_requires_approval_when_matching_rule_requires_it() -> None:
    engine = PolicyEngine(
        rules=(
            PolicyRule(
                rule_id="approve-delete",
                effect="require_approval",
                operations=("delete_vm", "vm.delete"),
                resource_type="vm",
                priority=10,
            ),
        )
    )

    decision = engine.evaluate("delete_vm", PolicyTarget(resource_type="vm", resource_id="100"))

    assert decision.decision == "requires_approval"
    assert decision.matched_rules == ["approve-delete"]


def test_policy_ignores_disabled_rules() -> None:
    engine = PolicyEngine(
        rules=(
            PolicyRule(
                rule_id="disabled-deny",
                effect="deny",
                operations=("vm.lifecycle.start",),
                enabled=False,
            ),
            PolicyRule(rule_id="allow-start", effect="allow", operations=("vm.lifecycle.start",)),
        )
    )

    decision = engine.evaluate("vm.lifecycle.start", PolicyTarget(resource_type="vm"))

    assert decision.decision == "allowed"
    assert decision.matched_rules == ["allow-start"]
