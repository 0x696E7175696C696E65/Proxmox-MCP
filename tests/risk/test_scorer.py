from __future__ import annotations

from proxmox_mcp.config import DangerousOperationSettings
from proxmox_mcp.risk import DangerousOperationRegistry, RiskScorer
from proxmox_mcp.schemas.envelope import Actor, RiskLevel, Target, ToolRequest
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition


async def noop_handler(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    return {"request_id": request.request_id, "context_id": context.request_id}


def make_definition(
    *,
    name: str,
    permission: str,
    risk: RiskLevel,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        category="vm",
        permission=permission,
        risk=risk,
        dry_run=False,
        approval_default=False,
        connector="proxmox_api",
        handler=noop_handler,
    )


def test_risk_scorer_marks_default_dangerous_operation_as_critical() -> None:
    scorer = RiskScorer(registry=DangerousOperationRegistry.default())
    definition = make_definition(name="delete_vm", permission="vm.delete", risk="medium")
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1"),
        target=Target(resource_type="vm", resource_id="100"),
    )

    risk = scorer.score(definition, request)

    assert risk.level == "critical"
    assert risk.score == 95
    assert risk.dangerous_operation is True
    assert "delete_vm" in risk.reasons


def test_risk_scorer_keeps_non_dangerous_low_risk_operation_low() -> None:
    scorer = RiskScorer(registry=DangerousOperationRegistry.default())
    definition = make_definition(name="vm_status", permission="vm.read", risk="low")
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1"),
        target=Target(resource_type="vm", resource_id="100"),
    )

    risk = scorer.score(definition, request)

    assert risk.level == "low"
    assert risk.score == 10
    assert risk.dangerous_operation is False
    assert risk.reasons == ["vm.read"]


def test_risk_scorer_reports_disabled_dangerous_operation_controls() -> None:
    scorer = RiskScorer(
        registry=DangerousOperationRegistry.default(
            settings=DangerousOperationSettings(enabled=False)
        )
    )
    definition = make_definition(name="execute_ssh", permission="ssh.execute", risk="high")
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1"),
        target=Target(resource_type="node", resource_id="pve-1", node="pve-1"),
    )

    risk = scorer.score(definition, request)

    assert risk.level == "critical"
    assert risk.dangerous_operation is True
    assert "dangerous_operation_controls_disabled" in risk.reasons


def test_risk_scorer_lowers_dry_run_score_without_lowering_dangerous_level() -> None:
    scorer = RiskScorer(registry=DangerousOperationRegistry.default())
    definition = make_definition(name="delete_vm", permission="vm.delete", risk="critical")
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1"),
        target=Target(resource_type="vm", resource_id="100"),
    )

    risk = scorer.score(definition, request, dry_run=True)

    assert risk.level == "critical"
    assert risk.score == 80
    assert risk.dangerous_operation is True
