from __future__ import annotations

from datetime import UTC, datetime, timedelta

from proxmox_mcp.approvals import (
    ApprovalStatus,
    ApprovalValidator,
    InMemoryApprovalStore,
    StoredApproval,
    canonical_json_hash,
    hash_approval_token,
)
from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.schemas.envelope import Target

APPROVAL_CODE = "approved-request-code"
WRONG_APPROVAL_CODE = "wrong-request-code"


def make_approval(
    *,
    now: datetime,
    actor_user_id: str = "user_1",
    actor_agent_id: str = "agent_1",
    target: Target | None = None,
    input_payload: dict[str, object] | None = None,
    approval_token: str | None = None,
    status: ApprovalStatus = "approved",
) -> StoredApproval:
    target = Target(resource_type="vm", resource_id="100") if target is None else target
    input_payload = {"force": True} if input_payload is None else input_payload
    approval_token = APPROVAL_CODE if approval_token is None else approval_token
    return StoredApproval(
        approval_request_id="apr_1",
        operation="delete_vm",
        target_hash=canonical_json_hash(target.model_dump(mode="json")),
        input_hash=canonical_json_hash(input_payload),
        approval_token_hash=hash_approval_token(approval_token),
        actor_user_id=actor_user_id,
        actor_agent_id=actor_agent_id,
        actor_tenant_id="tenant_1",
        risk_level="critical",
        risk_score=95,
        expires_at=now + timedelta(minutes=5),
        status=status,
    )


def test_approval_validator_accepts_matching_approved_request() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    target = Target(resource_type="vm", resource_id="100")
    payload: dict[str, object] = {"force": True}
    approval = make_approval(now=now, target=target, input_payload=payload)

    result = ApprovalValidator().validate(
        approval,
        approval_token=APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        operation="delete_vm",
        target=target,
        input_payload=payload,
        risk_level="critical",
        risk_score=95,
        now=now,
    )

    assert result.valid is True
    assert result.error_code is None


def test_approval_validator_rejects_expired_approval() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    approval = make_approval(now=now)

    result = ApprovalValidator().validate(
        approval,
        approval_token=APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        operation="delete_vm",
        target=Target(resource_type="vm", resource_id="100"),
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
        now=now + timedelta(minutes=6),
    )

    assert result.valid is False
    assert result.error_code == "APPROVAL_EXPIRED"


def test_approval_validator_rejects_actor_mismatch() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    result = ApprovalValidator().validate(
        make_approval(now=now),
        approval_token=APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_2", agent_id="agent_1", tenant_id="tenant_1"),
        operation="delete_vm",
        target=Target(resource_type="vm", resource_id="100"),
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
        now=now,
    )

    assert result.valid is False
    assert result.error_code == "APPROVAL_SCOPE_MISMATCH"


def test_approval_validator_rejects_target_mismatch() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    result = ApprovalValidator().validate(
        make_approval(now=now),
        approval_token=APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        operation="delete_vm",
        target=Target(resource_type="vm", resource_id="101"),
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
        now=now,
    )

    assert result.valid is False
    assert result.error_code == "APPROVAL_SCOPE_MISMATCH"


def test_approval_validator_rejects_input_mismatch() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    result = ApprovalValidator().validate(
        make_approval(now=now),
        approval_token=APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        operation="delete_vm",
        target=Target(resource_type="vm", resource_id="100"),
        input_payload={"force": False},
        risk_level="critical",
        risk_score=95,
        now=now,
    )

    assert result.valid is False
    assert result.error_code == "APPROVAL_SCOPE_MISMATCH"


def test_approval_validator_rejects_non_approved_status() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    result = ApprovalValidator().validate(
        make_approval(now=now, status="pending"),
        approval_token=APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        operation="delete_vm",
        target=Target(resource_type="vm", resource_id="100"),
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
        now=now,
    )

    assert result.valid is False
    assert result.error_code == "APPROVAL_REQUIRED"


def test_approval_validator_rejects_token_mismatch() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    result = ApprovalValidator().validate(
        make_approval(now=now),
        approval_token=WRONG_APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        operation="delete_vm",
        target=Target(resource_type="vm", resource_id="100"),
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
        now=now,
    )

    assert result.valid is False
    assert result.error_code == "APPROVAL_SCOPE_MISMATCH"


def test_approval_validator_rejects_actor_tenant_mismatch() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    result = ApprovalValidator().validate(
        make_approval(now=now),
        approval_token=APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_2"),
        operation="delete_vm",
        target=Target(resource_type="vm", resource_id="100"),
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
        now=now,
    )

    assert result.valid is False
    assert result.error_code == "APPROVAL_SCOPE_MISMATCH"


def test_approval_validator_rejects_risk_mismatch() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)

    result = ApprovalValidator().validate(
        make_approval(now=now),
        approval_token=APPROVAL_CODE,
        actor=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        operation="delete_vm",
        target=Target(resource_type="vm", resource_id="100"),
        input_payload={"force": True},
        risk_level="high",
        risk_score=75,
        now=now,
    )

    assert result.valid is False
    assert result.error_code == "APPROVAL_SCOPE_MISMATCH"


def test_in_memory_approval_store_consumes_approval_once() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    approval = make_approval(now=now)
    store = InMemoryApprovalStore((approval,))
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1")
    target = Target(resource_type="vm", resource_id="100")

    first = store.consume(
        APPROVAL_CODE,
        actor=actor,
        operation="delete_vm",
        target=target,
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
        now=now,
    )
    second = store.consume(
        APPROVAL_CODE,
        actor=actor,
        operation="delete_vm",
        target=target,
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
        now=now,
    )

    assert first.valid is True
    assert second.valid is False
    assert second.error_code == "APPROVAL_SCOPE_MISMATCH"
