from __future__ import annotations

from collections.abc import Awaitable, Sequence
from datetime import UTC, datetime
from inspect import isawaitable
from typing import TYPE_CHECKING, Protocol

from proxmox_mcp.approvals import ApprovalValidationResult
from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.policy import PolicyDecision as DomainPolicyDecision
from proxmox_mcp.policy import PolicyEngine, PolicyTarget
from proxmox_mcp.rbac import AccessTarget, RBACEvaluator, RoleAssignment
from proxmox_mcp.risk import DangerousOperationRegistry, RiskScorer
from proxmox_mcp.schemas.envelope import (
    ApprovalInfo,
    Impact,
    PolicyDecision,
    ResourceRef,
    RiskLevel,
    Target,
    ToolRequest,
)
from proxmox_mcp.security.rate_limit import DRY_RUN_LIMITER
from proxmox_mcp.tools.context import ToolExecutionContext

if TYPE_CHECKING:
    from proxmox_mcp.tools.registry import ToolDefinition, ToolGuardDecision


class ApprovalConsumer(Protocol):
    def consume(
        self,
        approval_token: str | None,
        *,
        actor: ActorIdentity,
        operation: str,
        target: Target,
        input_payload: object,
        risk_level: RiskLevel,
        risk_score: int,
    ) -> ApprovalValidationResult | Awaitable[ApprovalValidationResult]: ...


class SecurityPlaneGuard:
    def __init__(
        self,
        *,
        role_assignments: Sequence[RoleAssignment] = (),
        policy_engine: PolicyEngine | None = None,
        approval_store: ApprovalConsumer | None = None,
        rbac_evaluator: RBACEvaluator | None = None,
    ) -> None:
        self._role_assignments = tuple(role_assignments)
        self._policy_engine = PolicyEngine() if policy_engine is None else policy_engine
        self._approval_store = approval_store
        self._rbac_evaluator = RBACEvaluator() if rbac_evaluator is None else rbac_evaluator

    def _tool_acl_allows(self, actor: ActorIdentity, tool_name: str) -> bool:
        """Enforce per-tool ACL from matching role assignments (deny-by-default when set)."""
        matched = False
        for assignment in self._role_assignments:
            if not assignment.applies_to(actor):
                continue
            matched = True
            if self._rbac_evaluator.tool_allowed(assignment.role, tool_name):
                return True
        # No assignment matched → fail closed only when some assignment exists globally
        # with explicit tool grants; otherwise legacy permission-only path already ran.
        if not matched:
            return False
        # Assignments matched but none granted the tool.
        explicit = any(
            a.applies_to(actor) and a.role.granted_tools is not None
            for a in self._role_assignments
        )
        return not explicit

    async def evaluate(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolGuardDecision:
        from proxmox_mcp.tools.registry import ToolGuardDecision

        risk = RiskScorer(
            registry=DangerousOperationRegistry.default(
                settings=context.settings.dangerous_operations
            )
        ).score(definition, request)
        impact = _impact_for(request)

        if definition.connector == "internal" and definition.name == "health_check":
            return ToolGuardDecision.allowed(
                risk=risk,
                policy=PolicyDecision(decision="allow"),
                approval=ApprovalInfo(required=False),
                impact=impact,
            )

        actor = _authenticated_actor(context)
        if actor is None:
            return ToolGuardDecision.denied(
                error_code="AUTHENTICATION_REQUIRED",
                message="Authentication required for non-internal tool execution",
                risk=risk,
                policy=PolicyDecision(decision="deny", reason="authentication_required"),
                approval=ApprovalInfo(required=False),
                impact=impact,
            )

        if not _request_actor_matches_session(request, actor):
            return ToolGuardDecision.denied(
                error_code="AUTHENTICATION_FAILED",
                message="Request actor does not match authenticated identity",
                risk=risk,
                policy=PolicyDecision(decision="deny", reason="actor_mismatch"),
                approval=ApprovalInfo(required=False),
                impact=impact,
            )

        if not self._rbac_evaluator.is_allowed(
            actor,
            definition.permission,
            _access_target_for(request),
            self._role_assignments,
        ):
            return ToolGuardDecision.denied(
                error_code="RBAC_DENIED",
                message="Actor is not authorized for this tool",
                risk=risk,
                policy=PolicyDecision(decision="deny", reason="rbac_denied"),
                approval=ApprovalInfo(required=False),
                impact=impact,
                details={
                    "denial_reason": "RBAC_DENIED",
                    "matched_rule": definition.permission,
                    "tool_name": definition.name,
                },
            )

        if not self._tool_acl_allows(actor, definition.name):
            return ToolGuardDecision.denied(
                error_code="TOOL_NOT_GRANTED",
                message="Actor is not granted this tool by capability role ACL",
                risk=risk,
                policy=PolicyDecision(decision="deny", reason="tool_not_granted"),
                approval=ApprovalInfo(required=False),
                impact=impact,
                details={
                    "denial_reason": "TOOL_NOT_GRANTED",
                    "matched_rule": definition.name,
                    "tool_name": definition.name,
                },
            )

        if request.options.dry_run and definition.dry_run:
            dry_run_key = f"dry_run:{actor.user_id}:{actor.agent_id}"
            if DRY_RUN_LIMITER.is_limited(dry_run_key):
                return ToolGuardDecision.denied(
                    error_code="RATE_LIMITED",
                    message="Dry-run rate limit exceeded for this actor",
                    risk=risk,
                    policy=PolicyDecision(decision="deny", reason="dry_run_rate_limited"),
                    approval=ApprovalInfo(required=False),
                    impact=impact,
                )
            DRY_RUN_LIMITER.record_failure(dry_run_key)

        if risk.dangerous_operation and not context.settings.dangerous_operations.enabled:
            return ToolGuardDecision.denied(
                error_code="DANGEROUS_OPERATION_DISABLED",
                message="Dangerous operations are disabled",
                risk=risk,
                policy=PolicyDecision(decision="deny", reason="dangerous_operations_disabled"),
                approval=ApprovalInfo(required=False),
                impact=impact,
            )

        policy = self._policy_engine.evaluate(
            definition.permission,
            _policy_target_for(request),
        )
        if policy.decision == "denied":
            return ToolGuardDecision.denied(
                error_code="POLICY_DENIED",
                message="Policy denied this tool execution",
                risk=risk,
                policy=_envelope_policy(policy),
                approval=ApprovalInfo(required=False),
                impact=impact,
            )

        approval_required = not request.options.dry_run and (
            policy.decision == "requires_approval"
            or definition.approval_default
            or (
                definition.dry_run
                and _mutations_require_approval(context.settings)
            )
            or (risk.dangerous_operation and context.settings.dangerous_operations.require_approval)
        )
        if not approval_required:
            return ToolGuardDecision.allowed(
                risk=risk,
                policy=_envelope_policy(policy),
                approval=ApprovalInfo(required=False),
                impact=impact,
            )

        approval_info = ApprovalInfo(required=True)
        if self._approval_store is None:
            return ToolGuardDecision.requires_approval(
                risk=risk,
                policy=PolicyDecision(
                    decision="requires_approval",
                    matched_rules=policy.matched_rules,
                ),
                approval=approval_info,
                impact=impact,
                message="Approval store unavailable; cannot queue approval request",
            )

        if (
            request.options.approval_token is None
            and request.options.approval_request_id is None
        ):
            queue_fn = getattr(self._approval_store, "queue_pending", None)
            if queue_fn is None:
                return ToolGuardDecision.requires_approval(
                    risk=risk,
                    policy=PolicyDecision(
                        decision="requires_approval",
                        matched_rules=policy.matched_rules,
                    ),
                    approval=approval_info,
                    impact=impact,
                )
            queued = queue_fn(
                operation=definition.permission,
                target=request.target,
                input_payload=request.parameters,
                actor=actor,
                risk_level=risk.level,
                risk_score=risk.score,
                summary={
                    "tool_name": definition.name,
                    "permission": definition.permission,
                    "resource_type": request.target.resource_type,
                    "resource_id": request.target.resource_id,
                    "node": request.target.node,
                    "vmid": request.target.vmid,
                },
            )
            if isawaitable(queued):
                queued = await queued
            if getattr(queued, "created", False):
                try:
                    from proxmox_mcp.approvals.webhook import (
                        build_approval_queued_payload,
                        maybe_dispatch_approval_queued,
                    )

                    payload = build_approval_queued_payload(
                        approval_request_id=queued.approval_request_id,
                        operation=definition.permission,
                        risk_level=risk.level,
                        expires_at=queued.expires_at.isoformat(),
                        actor_user_id=actor.user_id,
                        actor_agent_id=actor.agent_id,
                    )
                    await maybe_dispatch_approval_queued(
                        settings=context.settings,
                        payload=payload,
                    )
                except Exception:  # noqa: BLE001 - never fail mint on notify
                    pass
            return ToolGuardDecision.requires_approval(
                message=(
                    "Tool execution requires approval. After an admin approves "
                    f"request {queued.approval_request_id}, retry with options."
                    "approval_request_id and options.approval_resume_secret "
                    "(preferred closed-loop; no token paste) or the one-time "
                    "approval_token."
                ),
                approval_request_id=queued.approval_request_id,
                resume_secret=getattr(queued, "resume_secret", None),
                risk=risk,
                policy=PolicyDecision(
                    decision="requires_approval",
                    matched_rules=policy.matched_rules,
                ),
                approval=ApprovalInfo(
                    required=True,
                    approval_request_id=queued.approval_request_id,
                ),
                impact=impact,
            )

        if request.options.approval_request_id is not None:
            consume_by_id = getattr(self._approval_store, "consume_by_request_id", None)
            if consume_by_id is None:
                return ToolGuardDecision.denied(
                    error_code="APPROVAL_SCOPE_MISMATCH",
                    message="Approval store does not support request-id consume",
                    risk=risk,
                    policy=PolicyDecision(
                        decision="requires_approval",
                        matched_rules=policy.matched_rules,
                    ),
                    approval=approval_info,
                    impact=impact,
                )
            approval = consume_by_id(
                request.options.approval_request_id,
                actor=actor,
                operation=definition.permission,
                target=request.target,
                input_payload=request.parameters,
                risk_level=risk.level,
                risk_score=risk.score,
                resume_secret=request.options.approval_resume_secret,
            )
        else:
            approval = self._approval_store.consume(
                request.options.approval_token,
                actor=actor,
                operation=definition.permission,
                target=request.target,
                input_payload=request.parameters,
                risk_level=risk.level,
                risk_score=risk.score,
            )
        if isawaitable(approval):
            approval = await approval
        if not approval.valid:
            return ToolGuardDecision.denied(
                error_code=approval.error_code or "APPROVAL_SCOPE_MISMATCH",
                message="Approval validation failed",
                risk=risk,
                policy=PolicyDecision(
                    decision="requires_approval",
                    matched_rules=policy.matched_rules,
                ),
                approval=approval_info,
                impact=impact,
            )

        return ToolGuardDecision.allowed(
            risk=risk,
            policy=_envelope_policy(policy),
            approval=ApprovalInfo(required=True),
            impact=impact,
        )


def _access_target_for(request: ToolRequest) -> AccessTarget:
    return AccessTarget(
        resource_type=request.target.resource_type,
        resource_id=request.target.resource_id,
        tenant_id=request.target.tenant_id,
        cluster=request.target.cluster,
        node=request.target.node,
        vmid=request.target.vmid,
        storage_id=request.target.storage_id
        or (request.target.resource_id if request.target.resource_type == "storage" else None),
    )


def _policy_target_for(request: ToolRequest) -> PolicyTarget:
    return PolicyTarget(
        resource_type=request.target.resource_type,
        resource_id=request.target.resource_id,
        tenant_id=request.target.tenant_id,
        cluster=request.target.cluster,
        node=request.target.node,
    )


def _envelope_policy(policy: DomainPolicyDecision) -> PolicyDecision:
    if policy.decision == "allowed":
        return PolicyDecision(decision="allow", matched_rules=policy.matched_rules)

    if policy.decision == "denied":
        return PolicyDecision(decision="deny", matched_rules=policy.matched_rules)

    return PolicyDecision(decision="requires_approval", matched_rules=policy.matched_rules)


def _impact_for(request: ToolRequest) -> Impact:
    return Impact(
        affected_resources=[
            ResourceRef(
                type=request.target.resource_type,
                id=request.target.resource_id,
                node=request.target.node,
            )
        ]
    )


def _authenticated_actor(context: ToolExecutionContext) -> ActorIdentity | None:
    session = context.authenticated_session
    if session is None:
        return None

    if session.status != "active" or session.expires_at <= datetime.now(UTC):
        return None

    return session.identity


def _request_actor_matches_session(request: ToolRequest, actor: ActorIdentity) -> bool:
    return (
        request.actor.user_id == actor.user_id
        and request.actor.agent_id == actor.agent_id
        and request.actor.tenant_id == actor.tenant_id
    )


def _mutations_require_approval(settings: object) -> bool:
    explicit = getattr(settings, "mutations_require_approval", None)
    if explicit is not None:
        return bool(explicit)
    environment = getattr(settings, "environment", "development")
    return environment != "test"
