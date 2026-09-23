"""Security hardening: C1–H3 / M1–M2 regression coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from proxmox_mcp.approvals import InMemoryApprovalStore
from proxmox_mcp.approvals.webhook import (
    is_webhook_timestamp_fresh,
    validate_approval_webhook_url,
)
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession, ServiceTokenAuthenticator
from proxmox_mcp.config import DangerousOperationSettings, Settings
from proxmox_mcp.rbac import Role, RoleAssignment, Scope, role_from_mcp_name
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.server.auth_resolver import authenticate_bearer_token, resolve_mcp_role
from proxmox_mcp.server.app import _runtime_role_assignments
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolGuardDecision


async def _noop(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    return {"ok": True}


def _mutation_definition(*, approval_default: bool = False) -> ToolDefinition:
    return ToolDefinition(
        name="create_vm",
        description="Create VM",
        category="vm",
        permission="vm.create",
        risk="high",
        dry_run=True,
        approval_default=approval_default,
        connector="proxmox_api",
        handler=_noop,
    )


def _session(
    *,
    user_id: str = "operator",
    agent_id: str = "homelab-agent",
) -> AuthenticatedSession:
    issued = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess",
        identity=ActorIdentity(user_id=user_id, agent_id=agent_id, tenant_id=None),
        auth_method="service_token",
        status="active",
        issued_at=issued,
        expires_at=issued + timedelta(hours=1),
    )


def _request(
    *,
    dry_run: bool = False,
    approval_token: str | None = None,
    approval_request_id: str | None = None,
    approval_resume_secret: str | None = None,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="operator", agent_id="homelab-agent"),
        target=Target(resource_type="vm", resource_id="100", node="pve1"),
        parameters={"name": "x"},
        options=RequestOptions(
            dry_run=dry_run,
            approval_token=approval_token,
            approval_request_id=approval_request_id,
            approval_resume_secret=approval_resume_secret,
        ),
    )


def _context(
    request: ToolRequest,
    *,
    environment: str = "homelab",
    mutations_require_approval: bool | None = None,
    session: AuthenticatedSession | None = None,
) -> ToolExecutionContext:
    kwargs: dict[str, object] = {"environment": environment}
    if mutations_require_approval is not None:
        kwargs["mutations_require_approval"] = mutations_require_approval
    return ToolExecutionContext(
        request=request,
        settings=Settings(**kwargs),  # type: ignore[arg-type]
        audit_writer=MagicMock(),
        authenticated_session=session or _session(),
    )


@pytest.mark.asyncio
async def test_c2_live_mutation_requires_approval_even_without_approval_default() -> None:
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
    request = _request(dry_run=False)
    decision = await guard.evaluate(
        _mutation_definition(approval_default=False),
        request,
        _context(request, environment="homelab"),
    )
    assert isinstance(decision, ToolGuardDecision)
    assert decision.decision == "requires_approval"
    assert decision.approval is not None and decision.approval.required is True
    assert decision.approval.approval_request_id is not None


@pytest.mark.asyncio
async def test_h3_g1_consume_via_approval_request_id_without_token() -> None:
    store = InMemoryApprovalStore()
    guard = SecurityPlaneGuard(
        role_assignments=(
            RoleAssignment(
                actor_user_id="operator",
                actor_agent_id="homelab-agent",
                role=Role.administrator(),
                scope=Scope(),
            ),
        ),
        approval_store=store,
    )
    request = _request(dry_run=False)
    mint = await guard.evaluate(
        _mutation_definition(approval_default=True),
        request,
        _context(request, environment="homelab", session=_session()),
    )
    assert mint.decision == "requires_approval"
    assert mint.approval is not None
    approval_id = mint.approval.approval_request_id
    assert approval_id is not None
    resume_secret = mint.details.get("approval_resume_secret")
    assert isinstance(resume_secret, str) and resume_secret

    decided = await store.decide(
        approval_id,
        decision="approved",
        decided_by="admin",
        decided_by_user_id="admin-user-1",
    )
    assert decided is not None
    assert decided.quorum_pending is True
    decided = await store.decide(
        approval_id,
        decision="approved",
        decided_by="admin2",
        decided_by_user_id="admin-user-2",
    )
    assert decided is not None
    assert decided.approval_token is not None

    # Closed-loop steal without resume_secret must fail
    stolen = _request(dry_run=False, approval_request_id=approval_id)
    denied = await guard.evaluate(
        _mutation_definition(approval_default=True),
        stolen,
        _context(stolen, environment="homelab", session=_session()),
    )
    assert denied.decision == "denied"

    retry = _request(
        dry_run=False,
        approval_request_id=approval_id,
        approval_resume_secret=resume_secret,
    )
    decision = await guard.evaluate(
        _mutation_definition(approval_default=True),
        retry,
        _context(retry, environment="homelab", session=_session()),
    )
    assert decision.decision == "allowed"

    # One-time: second consume by request id fails
    decision2 = await guard.evaluate(
        _mutation_definition(approval_default=True),
        retry,
        _context(retry, environment="homelab", session=_session()),
    )
    assert decision2.decision == "denied"


@pytest.mark.asyncio
async def test_h2_sod_rejects_approver_matching_actor() -> None:
    store = InMemoryApprovalStore()
    queued = await store.queue_pending(
        operation="vm.delete",
        target=Target(resource_type="vm", resource_id="1"),
        input_payload={},
        actor=ActorIdentity(user_id="admin", agent_id="homelab-agent"),
        risk_level="high",
        risk_score=80,
    )
    result = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin",
        decided_by_user_id="admin",
    )
    assert result is not None
    assert result.error_code == "SOD_VIOLATION"
    assert result.approval_token is None


def test_c1_g2_default_mcp_role_is_read_only() -> None:
    settings = Settings(
        environment="homelab",
        auth_mode="service_token",
        service_token="x" * 32,
    )
    assert settings.mcp_service_role == "read_only"
    role = resolve_mcp_role(settings.mcp_service_role)
    assert role.name == "ReadOnly"
    assignments = _runtime_role_assignments(settings)
    mcp_roles = {
        a.role.name
        for a in assignments
        if a.actor_agent_id == settings.default_actor.agent_id
    }
    assert "Administrator" not in mcp_roles
    assert "ClusterAdmin" not in mcp_roles
    assert "ReadOnly" in mcp_roles
    assert any(a.role.name == "AdminConsole" and a.actor_agent_id == "admin-ui" for a in assignments)


def test_shared_token_elevated_role_requires_break_glass() -> None:
    with pytest.raises(ValueError, match="ALLOW_SHARED_SERVICE_TOKEN_ELEVATED_ROLE"):
        Settings(
            environment="homelab",
            auth_mode="service_token",
            service_token="x" * 32,
            mcp_service_role="cluster_admin",
        )
    ok = Settings(
        environment="homelab",
        auth_mode="service_token",
        service_token="x" * 32,
        mcp_service_role="cluster_admin",
        allow_shared_service_token_elevated_role=True,
    )
    assert ok.mcp_service_role == "cluster_admin"


def test_h1_secondary_service_token_binds_distinct_actor() -> None:
    primary = "primary-token-value-32chars-min!!"
    secondary = "secondary-token-value-32chars-min"
    settings = Settings(
        environment="homelab",
        auth_mode="service_token",
        service_token=primary,
        service_token_actors=(
            {
                "token_sha256": ServiceTokenAuthenticator.sha256_token_hash(secondary),
                "user_id": "reader",
                "agent_id": "cursor-readonly",
                "role": "read_only",
            },
        ),
    )
    primary_session = authenticate_bearer_token(settings, primary)
    secondary_session = authenticate_bearer_token(settings, secondary)
    assert primary_session is not None
    assert secondary_session is not None
    assert primary_session.identity.agent_id == settings.default_actor.agent_id
    assert secondary_session.identity.user_id == "reader"
    assert secondary_session.identity.agent_id == "cursor-readonly"


def test_m1_webhook_rejects_private_and_stale_timestamp() -> None:
    with pytest.raises(ValueError):
        validate_approval_webhook_url("https://127.0.0.1/hook")
    with pytest.raises(ValueError):
        validate_approval_webhook_url("https://169.254.169.254/latest")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert is_webhook_timestamp_fresh("2026-01-01T12:00:00+00:00", now=now, max_skew_seconds=300)
    assert not is_webhook_timestamp_fresh(
        "2026-01-01T11:00:00+00:00", now=now, max_skew_seconds=300
    )


def test_c3_expand_storage_rejects_shell_metacharacters() -> None:
    from proxmox_mcp.proxmox.domain_tools import _validate_lvmthin_expand_args
    from proxmox_mcp.tools.registry import ToolExecutionError

    with pytest.raises(ToolExecutionError, match="Unsafe|invalid"):
        _validate_lvmthin_expand_args(
            requested_size="10G; id",
            vgname="vg0",
            thinpool="data",
        )
    with pytest.raises(ToolExecutionError):
        _validate_lvmthin_expand_args(
            requested_size="10G",
            vgname="vg0$(reboot)",
            thinpool="data",
        )
    _validate_lvmthin_expand_args(requested_size="+10G", vgname="pve", thinpool="data")


def test_role_from_mcp_name_roundtrip() -> None:
    assert role_from_mcp_name("read_only").name == "ReadOnly"
    assert role_from_mcp_name("operator").name == "Operator"
    assert role_from_mcp_name("cluster_admin").name == "ClusterAdmin"
    assert role_from_mcp_name("administrator").name == "Administrator"
