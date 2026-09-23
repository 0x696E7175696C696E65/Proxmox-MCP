"""D3/D13/D14/D15 closed-loop resume, dry-run defaults, schema, RBAC packs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from proxmox_mcp.approvals import InMemoryApprovalStore
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.rbac import AccessTarget, RBACEvaluator, Role, RoleAssignment, Scope
from proxmox_mcp.schemas.envelope import Actor, MutatorRequestOptions, RequestOptions, Target, ToolRequest
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.security.rate_limit import DRY_RUN_LIMITER
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolRegistry


async def _noop(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    return {"ok": True}


def _session() -> AuthenticatedSession:
    issued = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess",
        identity=ActorIdentity(user_id="operator", agent_id="homelab-agent"),
        auth_method="service_token",
        status="active",
        issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )


def _mutation() -> ToolDefinition:
    return ToolDefinition(
        name="create_vm",
        description="Create VM",
        category="vm",
        permission="vm.create",
        risk="high",
        dry_run=True,
        approval_default=True,
        connector="proxmox_api",
        handler=_noop,
    )


def _context(request: ToolRequest) -> ToolExecutionContext:
    from proxmox_mcp.audit.writer import InMemoryAuditWriter

    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="homelab", auth_mode="service_token", service_token="x" * 32),
        audit_writer=InMemoryAuditWriter(),
        authenticated_session=_session(),
    )


@pytest.mark.asyncio
async def test_d3_mint_returns_resume_secret_once_and_remint_omits_it() -> None:
    store = InMemoryApprovalStore()
    first = await store.queue_pending(
        operation="vm.create",
        target=Target(resource_type="vm", resource_id="100", node="pve1"),
        input_payload={"name": "x"},
        actor=ActorIdentity(user_id="operator", agent_id="homelab-agent"),
        risk_level="high",
        risk_score=75,
    )
    assert first.created is True
    assert isinstance(first.resume_secret, str) and first.resume_secret

    second = await store.queue_pending(
        operation="vm.create",
        target=Target(resource_type="vm", resource_id="100", node="pve1"),
        input_payload={"name": "x"},
        actor=ActorIdentity(user_id="operator", agent_id="homelab-agent"),
        risk_level="high",
        risk_score=75,
    )
    assert second.created is False
    assert second.approval_request_id == first.approval_request_id
    assert second.resume_secret is None


@pytest.mark.asyncio
async def test_d3_consume_by_request_id_requires_matching_resume_secret() -> None:
    store = InMemoryApprovalStore()
    queued = await store.queue_pending(
        operation="vm.create",
        target=Target(resource_type="vm", resource_id="100", node="pve1"),
        input_payload={"name": "x"},
        actor=ActorIdentity(user_id="operator", agent_id="homelab-agent"),
        risk_level="high",
        risk_score=75,
    )
    assert queued.resume_secret is not None
    first = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin",
        decided_by_user_id="admin-user-1",
    )
    assert first is not None and first.quorum_pending is True
    decided = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin2",
        decided_by_user_id="admin-user-2",
    )
    assert decided is not None and decided.approval_token is not None

    actor = ActorIdentity(user_id="operator", agent_id="homelab-agent")
    target = Target(resource_type="vm", resource_id="100", node="pve1")
    bad = store.consume_by_request_id(
        queued.approval_request_id,
        actor=actor,
        operation="vm.create",
        target=target,
        input_payload={"name": "x"},
        risk_level="high",
        risk_score=75,
        resume_secret="wrong-secret",
    )
    assert bad.valid is False

    missing = store.consume_by_request_id(
        queued.approval_request_id,
        actor=actor,
        operation="vm.create",
        target=target,
        input_payload={"name": "x"},
        risk_level="high",
        risk_score=75,
    )
    assert missing.valid is False

    ok = store.consume_by_request_id(
        queued.approval_request_id,
        actor=actor,
        operation="vm.create",
        target=target,
        input_payload={"name": "x"},
        risk_level="high",
        risk_score=75,
        resume_secret=queued.resume_secret,
    )
    assert ok.valid is True


def test_d13_mutator_options_default_dry_run_true() -> None:
    assert MutatorRequestOptions().dry_run is True
    assert RequestOptions().dry_run is False


def test_d14_mutator_schema_exposes_approval_resume_fields() -> None:
    registry = ToolRegistry()
    schema = registry.fastmcp_input_schema(_mutation())
    options = schema["$defs"]["MutatorRequestOptions"]["properties"]
    assert "approval_request_id" in options
    assert "approval_resume_secret" in options
    assert options["dry_run"].get("default") is True


def test_d15_readonly_covers_network_monitoring_helper_reads() -> None:
    evaluator = RBACEvaluator()
    actor = ActorIdentity(user_id="ro", agent_id="agent")
    assignments = (
        RoleAssignment(role=Role.read_only(), scope=Scope(), actor_user_id="ro", actor_agent_id="agent"),
    )
    target = AccessTarget(resource_type="node", resource_id="pve1", node="pve1")
    for permission in (
        "network.config.read",
        "network.sdn.read",
        "monitoring.cpu.read",
        "monitoring.health.read",
        "helper.catalog.read",
        "helper.script.preview",
        "storage.iso.read",
    ):
        assert evaluator.is_allowed(actor, permission, target, assignments)


def test_d15_cluster_admin_helper_reads_without_execute() -> None:
    evaluator = RBACEvaluator()
    actor = ActorIdentity(user_id="ca", agent_id="agent")
    assignments = (
        RoleAssignment(
            role=Role.cluster_admin(),
            scope=Scope(),
            actor_user_id="ca",
            actor_agent_id="agent",
        ),
    )
    target = AccessTarget(resource_type="node", resource_id="pve1", node="pve1")
    assert evaluator.is_allowed(actor, "helper.catalog.read", target, assignments)
    assert not evaluator.is_allowed(actor, "helper.script.execute", target, assignments)


@pytest.mark.asyncio
async def test_d13_dry_run_rate_limit_trips() -> None:
    DRY_RUN_LIMITER.reset("dry_run:operator:homelab-agent")
    guard = SecurityPlaneGuard(
        role_assignments=(
            RoleAssignment(
                actor_user_id="operator",
                actor_agent_id="homelab-agent",
                role=Role.administrator(),
                scope=Scope(),
            ),
        ),
        approval_store=InMemoryApprovalStore(),
    )
    definition = ToolDefinition(
        name="create_vm",
        description="Create VM",
        category="vm",
        permission="vm.create",
        risk="high",
        dry_run=True,
        approval_default=False,
        connector="proxmox_api",
        handler=_noop,
    )
    # Force a tiny window for this test by exhausting the shared limiter.
    key = "dry_run:operator:homelab-agent"
    for _ in range(DRY_RUN_LIMITER.max_failures):
        DRY_RUN_LIMITER.record_failure(key)

    request = ToolRequest(
        actor=Actor(user_id="operator", agent_id="homelab-agent"),
        target=Target(resource_type="vm", resource_id="100", node="pve1"),
        parameters={},
        options=RequestOptions(dry_run=True),
    )
    decision = await guard.evaluate(definition, request, _context(request))
    assert decision.decision == "denied"
    assert decision.error_code == "RATE_LIMITED"
    DRY_RUN_LIMITER.reset(key)
