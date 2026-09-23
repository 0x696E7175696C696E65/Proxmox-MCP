from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from proxmox_mcp.config import DangerousOperationSettings
from proxmox_mcp.schemas.envelope import Risk, RiskLevel, ToolRequest

_RISK_SCORES: dict[RiskLevel, int] = {
    "low": 10,
    "medium": 50,
    "high": 75,
    "critical": 95,
}
_RISK_ORDER: dict[RiskLevel, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class ToolRiskDefinition(Protocol):
    name: str
    permission: str
    risk: RiskLevel


def _empty_operations() -> frozenset[str]:
    return frozenset()


@dataclass(frozen=True, slots=True)
class DangerousOperationRegistry:
    critical_operations: frozenset[str] = field(default_factory=_empty_operations)
    settings: DangerousOperationSettings = field(default_factory=DangerousOperationSettings)

    @classmethod
    def default(
        cls,
        *,
        settings: DangerousOperationSettings | None = None,
    ) -> DangerousOperationRegistry:
        operations: set[str] = {
            # Legacy aliases kept for permission-string variants.
            "vm.delete",
            "lxc.delete",
            "storage.delete",
            "disk.wipe",
            "wipe_disk",
            "storage.disk.wipe",
            "node.reboot",
            "node.shutdown",
            "vm.migrate.force",
            "force_migrate_vm",
            "ssh.execute",
            "execute_ssh",
            "ssh.command.execute",
            "firewall.disable",
            "firewall.permission.write",
            "permissions.write",
            "permission.write",
        }
        try:
            from proxmox_mcp.proxmox.dangerous_tools import DANGEROUS_TOOL_SPECS

            for spec in DANGEROUS_TOOL_SPECS:
                operations.add(spec.name)
                operations.add(spec.permission)
        except Exception:  # noqa: BLE001 - registry must still construct
            pass
        return cls(
            critical_operations=frozenset(operations),
            settings=DangerousOperationSettings() if settings is None else settings,
        )

    def matching_operations(self, definition: ToolRiskDefinition) -> tuple[str, ...]:
        candidates = (definition.name, definition.permission)
        return tuple(candidate for candidate in candidates if candidate in self.critical_operations)


class RiskScorer:
    def __init__(self, *, registry: DangerousOperationRegistry | None = None) -> None:
        self._registry = DangerousOperationRegistry.default() if registry is None else registry

    def score(
        self,
        definition: ToolRiskDefinition,
        request: ToolRequest,
        *,
        dry_run: bool | None = None,
    ) -> Risk:
        dangerous_matches = self._registry.matching_operations(definition)
        dangerous_operation = bool(dangerous_matches)
        risk_level = _max_risk_level(definition.risk, "critical" if dangerous_operation else "low")
        score = _RISK_SCORES[risk_level]
        effective_dry_run = request.options.dry_run if dry_run is None else dry_run

        if effective_dry_run:
            score = max(0, score - 15)

        reasons = _unique_reasons((definition.permission, *dangerous_matches))
        if dangerous_operation and not self._registry.settings.enabled:
            reasons.append("dangerous_operation_controls_disabled")

        if dangerous_operation and self._registry.settings.require_approval:
            reasons.append("dangerous_operation_approval_required")

        if request.target.node is not None:
            reasons.append(f"target_node:{request.target.node}")

        return Risk(
            level=risk_level,
            score=score,
            reasons=reasons,
            dangerous_operation=dangerous_operation,
        )


def _max_risk_level(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if _RISK_ORDER[left] >= _RISK_ORDER[right] else right


def _unique_reasons(reasons: tuple[str, ...]) -> list[str]:
    unique: list[str] = []
    for reason in reasons:
        if reason not in unique:
            unique.append(reason)

    return unique
