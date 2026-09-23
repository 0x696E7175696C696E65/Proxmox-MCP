from __future__ import annotations

import pytest

from proxmox_mcp.approvals import InMemoryApprovalStore
from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.schemas.envelope import Target


@pytest.mark.asyncio
async def test_critical_approval_requires_two_distinct_admins() -> None:
    store = InMemoryApprovalStore()
    queued = await store.queue_pending(
        operation="vm.delete",
        target=Target(resource_type="vm", resource_id="100"),
        input_payload={"force": True},
        actor=ActorIdentity(user_id="u1", agent_id="a1", tenant_id="t1"),
        risk_level="critical",
        risk_score=95,
    )
    first = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin1",
        decided_by_user_id="adminuser_1",
    )
    assert first is not None
    assert first.approval_token is None
    assert first.quorum_pending is True
    assert first.approval["required_approvals"] == 2
    assert first.approval["approval_count"] == 1

    dup = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin1",
        decided_by_user_id="adminuser_1",
    )
    assert dup is not None
    assert dup.error_code == "DUPLICATE_APPROVER"
    assert dup.approval_token is None

    second = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin2",
        decided_by_user_id="adminuser_2",
    )
    assert second is not None
    assert second.approval_token is not None
    assert second.quorum_pending is False
    assert second.approval["status"] == "approved"
    assert second.approval["approval_count"] == 2


@pytest.mark.asyncio
async def test_high_risk_requires_dual_control_by_default() -> None:
    store = InMemoryApprovalStore()
    queued = await store.queue_pending(
        operation="vm.lifecycle.stop",
        target=Target(resource_type="vm", resource_id="101"),
        input_payload={},
        actor=ActorIdentity(user_id="u1", agent_id="a1", tenant_id=None),
        risk_level="high",
        risk_score=80,
    )
    first = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin1",
        decided_by_user_id="adminuser_1",
    )
    assert first is not None
    assert first.approval_token is None
    assert first.quorum_pending is True
    assert first.approval["required_approvals"] == 2

    second = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin2",
        decided_by_user_id="adminuser_2",
    )
    assert second is not None
    assert second.approval_token is not None


@pytest.mark.asyncio
async def test_high_risk_single_approval_when_dual_control_disabled() -> None:
    store = InMemoryApprovalStore(dual_control_for_high=False)
    queued = await store.queue_pending(
        operation="vm.lifecycle.stop",
        target=Target(resource_type="vm", resource_id="101"),
        input_payload={},
        actor=ActorIdentity(user_id="u1", agent_id="a1", tenant_id=None),
        risk_level="high",
        risk_score=80,
    )
    decided = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin1",
        decided_by_user_id="adminuser_1",
    )
    assert decided is not None
    assert decided.approval_token is not None
    assert decided.approval["required_approvals"] == 1


@pytest.mark.asyncio
async def test_linked_identity_sod_blocks_dual_persona() -> None:
    store = InMemoryApprovalStore(
        sod_linked_identity_groups=(frozenset({"alice-operator", "alice-admin"}),)
    )
    queued = await store.queue_pending(
        operation="vm.delete",
        target=Target(resource_type="vm", resource_id="1"),
        input_payload={},
        actor=ActorIdentity(user_id="alice-operator", agent_id="homelab-agent"),
        risk_level="high",
        risk_score=80,
    )
    result = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="alice-admin",
        decided_by_user_id="alice-admin",
    )
    assert result is not None
    assert result.error_code == "SOD_VIOLATION"
    assert result.approval_token is None
