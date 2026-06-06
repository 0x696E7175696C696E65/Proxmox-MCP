from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

PolicyEffect = Literal["allow", "deny", "require_approval"]
PolicyDecisionValue = Literal["allowed", "denied", "requires_approval"]


def _empty_operations() -> tuple[str, ...]:
    return ()


def _empty_strings() -> frozenset[str]:
    return frozenset()


def _empty_matched_rules() -> list[str]:
    return []


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    effect: PolicyEffect
    operations: tuple[str, ...] = field(default_factory=_empty_operations)
    tenant_id: str | None = None
    cluster: str | None = None
    node: str | None = None
    resource_type: str | None = None
    resource_ids: frozenset[str] = field(default_factory=_empty_strings)
    priority: int = 0
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class PolicyTarget:
    resource_type: str
    resource_id: str | None = None
    tenant_id: str | None = None
    cluster: str | None = None
    node: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: PolicyDecisionValue
    matched_rules: list[str] = field(default_factory=_empty_matched_rules)


class PolicyEngine:
    def __init__(self, *, rules: tuple[PolicyRule, ...] = ()) -> None:
        self._rules = rules

    def evaluate(self, operation: str, target: PolicyTarget) -> PolicyDecision:
        matched_rules = [
            rule
            for rule in sorted(self._rules, key=lambda candidate: candidate.priority, reverse=True)
            if rule.enabled and self._matches_rule(rule, operation, target)
        ]
        matched_rule_ids = [rule.rule_id for rule in matched_rules]

        if any(rule.effect == "deny" for rule in matched_rules):
            return PolicyDecision(decision="denied", matched_rules=matched_rule_ids)

        if any(rule.effect == "require_approval" for rule in matched_rules):
            return PolicyDecision(decision="requires_approval", matched_rules=matched_rule_ids)

        return PolicyDecision(decision="allowed", matched_rules=matched_rule_ids)

    def _matches_rule(self, rule: PolicyRule, operation: str, target: PolicyTarget) -> bool:
        if rule.operations and not any(
            _operation_matches(candidate, operation) for candidate in rule.operations
        ):
            return False

        if rule.tenant_id is not None and target.tenant_id != rule.tenant_id:
            return False

        if rule.cluster is not None and target.cluster != rule.cluster:
            return False

        if rule.node is not None and target.node != rule.node:
            return False

        if rule.resource_type is not None and target.resource_type != rule.resource_type:
            return False

        if rule.resource_ids and target.resource_id not in rule.resource_ids:
            return False

        return True


def _operation_matches(pattern: str, operation: str) -> bool:
    if pattern == "*" or pattern == operation:
        return True

    if pattern.endswith(".*"):
        prefix = pattern.removesuffix(".*")
        return operation == prefix or operation.startswith(f"{prefix}.")

    return False
