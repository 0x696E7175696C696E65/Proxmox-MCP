import pytest
from pydantic import ValidationError

from proxmox_mcp.schemas.envelope import (
    Actor,
    ApprovalInfo,
    ApprovalRequest,
    AuditRef,
    IdempotencyScope,
    Impact,
    PaginationInput,
    PaginationOutput,
    PolicyDecision,
    RequestOptions,
    ResourceRef,
    Risk,
    Target,
    ToolError,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)


def test_tool_request_serializes_documented_request_envelope() -> None:
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_prod"),
        target=Target(cluster="prod-pve", node="pve-1", resource_type="vm", resource_id="100"),
        parameters={"state": "started"},
        options=RequestOptions(
            dry_run=True,
            explain_plan=True,
            include_impact_analysis=True,
            idempotency_key="idem_1",
            timeout_seconds=30,
        ),
    )

    dumped = request.model_dump(mode="json")

    assert dumped["request_id"].startswith("req_")
    assert dumped["correlation_id"] == dumped["request_id"]
    assert dumped["actor"]["user_id"] == "user_1"
    assert dumped["actor"]["tenant_id"] == "tenant_prod"
    assert dumped["target"]["cluster"] == "prod-pve"
    assert dumped["target"]["resource_type"] == "vm"
    assert dumped["parameters"] == {"state": "started"}
    assert dumped["options"]["dry_run"] is True
    assert "approval_token" in dumped["options"]


def test_tool_response_uses_documented_success_envelope_fields() -> None:
    response = ToolResponse(
        request_id="req_1",
        correlation_id="corr_1",
        dry_run=True,
        risk=Risk(
            level="high",
            score=72,
            reasons=["changes VM power state"],
            dangerous_operation=True,
        ),
        policy=PolicyDecision(
            decision="requires_approval",
            matched_rules=["prod-dangerous-vm-delete"],
        ),
        approval=ApprovalInfo(
            required=True,
            approval_request_id="appr_1",
            expires_at="2026-06-05T23:59:00Z",
        ),
        impact=Impact(
            affected_resources=[ResourceRef(type="vm", id="100", node="pve-1")],
            dependencies=[ResourceRef(type="backup_chain", id="pbs:vm/100")],
            estimated_downtime_seconds=300,
            data_loss_possible=False,
            network_disruption_possible=False,
            quorum_risk=False,
            rollback_available=True,
            rollback_suggestions=["Rollback to snapshot if startup fails."],
        ),
        result={"accepted": True},
        warnings=["maintenance window recommended"],
        rollback_suggestions=["Restore previous config."],
        audit=AuditRef(event_id="audit_1", recorded=True),
        pagination=PaginationOutput(next_cursor="cursor_2", has_more=True),
    )

    dumped = response.model_dump(mode="json")

    assert dumped["request_id"] == "req_1"
    assert dumped["correlation_id"] == "corr_1"
    assert dumped["status"] == "success"
    assert dumped["dry_run"] is True
    assert dumped["risk"]["level"] == "high"
    assert dumped["risk"]["score"] == 72
    assert dumped["risk"]["dangerous_operation"] is True
    assert dumped["policy"]["decision"] == "requires_approval"
    assert dumped["policy"]["matched_rules"] == ["prod-dangerous-vm-delete"]
    assert dumped["approval"]["approval_request_id"] == "appr_1"
    assert dumped["impact"]["affected_resources"][0]["type"] == "vm"
    assert dumped["result"] == {"accepted": True}
    assert dumped["warnings"] == ["maintenance window recommended"]
    assert dumped["rollback_suggestions"] == ["Restore previous config."]
    assert dumped["audit"]["event_id"] == "audit_1"
    assert dumped["audit"]["recorded"] is True
    assert dumped["pagination"]["next_cursor"] == "cursor_2"
    assert dumped["pagination"]["has_more"] is True


def test_tool_error_response_uses_documented_error_envelope_and_uppercase_codes() -> None:
    response = ToolErrorResponse(
        request_id="req_1",
        correlation_id="corr_1",
        error=ToolError(
            code="APPROVAL_REQUIRED",
            message="Approval is required before executing this tool.",
            retryable=False,
        ),
        audit=AuditRef(event_id="audit_2", recorded=True),
    )

    dumped = response.model_dump(mode="json")

    assert dumped["request_id"] == "req_1"
    assert dumped["correlation_id"] == "corr_1"
    assert dumped["status"] == "error"
    assert dumped["error"]["code"] == "APPROVAL_REQUIRED"
    assert dumped["audit"]["recorded"] is True


def test_approval_request_and_idempotency_models_are_explicit() -> None:
    actor = Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_prod")
    target = Target(cluster="prod-pve", node="pve-1", resource_type="vm", resource_id="100")
    risk = Risk(level="critical", score=95, reasons=["destructive_operation"])
    impact = Impact(affected_resources=[ResourceRef(type="vm", id="100")], data_loss_possible=True)

    approval = ApprovalRequest(
        approval_request_id="appr_1",
        operation="delete_vm",
        target_hash="sha256:target",
        input_hash="sha256:input",
        actor=actor,
        risk=risk,
        impact=impact,
        expires_at="2026-06-05T23:59:00Z",
        status="pending",
    )
    idempotency = IdempotencyScope(
        tenant_id="tenant_prod",
        actor=actor,
        tool_name="delete_vm",
        target=target,
        input_hash="sha256:input",
        idempotency_key="idem_1",
    )

    assert approval.approval_request_id == "appr_1"
    assert idempotency.idempotency_key == "idem_1"


def test_envelope_models_forbid_unexpected_fields() -> None:
    with pytest.raises(ValidationError):
        Actor.model_validate({"user_id": "user_1", "agent_id": "agent_1", "extra": True})


def test_risk_level_literals_reject_unknown_values() -> None:
    with pytest.raises(ValidationError):
        Risk.model_validate({"level": "extreme", "score": 1, "reasons": []})


def test_pagination_models_match_documented_shape() -> None:
    assert PaginationInput(limit=50).limit == 50
    assert PaginationOutput(next_cursor=None, has_more=False).has_more is False

    with pytest.raises(ValidationError):
        PaginationInput.model_validate({"limit": 0})
