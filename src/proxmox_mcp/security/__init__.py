from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
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
    ) -> ApprovalValidationResult: ...


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

        if definition.connector == "internal":
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
            )

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
        if self._approval_store is None or request.options.approval_token is None:
            return ToolGuardDecision.requires_approval(
                risk=risk,
                policy=PolicyDecision(
                    decision="requires_approval",
                    matched_rules=policy.matched_rules,
                ),
                approval=approval_info,
                impact=impact,
            )

        approval = self._approval_store.consume(
            request.options.approval_token,
            actor=actor,
            operation=definition.permission,
            target=request.target,
            input_payload=request.parameters,
            risk_level=risk.level,
            risk_score=risk.score,
        )
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
