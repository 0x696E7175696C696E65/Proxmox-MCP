from __future__ import annotations

from typing import Literal, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

RiskLevel = Literal["low", "medium", "high", "critical"]
ErrorCode = Literal[
    "INVALID_REQUEST",
    "AUTHENTICATION_REQUIRED",
    "AUTHENTICATION_FAILED",
    "SESSION_EXPIRED",
    "RBAC_DENIED",
    "POLICY_DENIED",
    "APPROVAL_REQUIRED",
    "APPROVAL_EXPIRED",
    "APPROVAL_SCOPE_MISMATCH",
    "DANGEROUS_OPERATION_DISABLED",
    "SECRET_UNAVAILABLE",
    "PROXMOX_API_ERROR",
    "PROXMOX_TASK_FAILED",
    "SSH_CONNECTION_FAILED",
    "SSH_COMMAND_FAILED",
    "SSH_POLICY_DENIED",
    "RATE_LIMITED",
    "CIRCUIT_OPEN",
    "AUDIT_WRITE_FAILED",
    "TIMEOUT",
    "CONFLICT",
    "NOT_FOUND",
    "INTERNAL_ERROR",
]
PolicyDecisionValue = Literal["allow", "deny", "requires_approval"]
ApprovalRequestStatus = Literal["pending", "approved", "rejected", "expired"]


def _new_request_id() -> str:
    return f"req_{uuid4().hex}"


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Actor(StrictBaseModel):
    user_id: str
    agent_id: str
    tenant_id: str | None = None


class Target(StrictBaseModel):
    tenant_id: str | None = None
    cluster: str | None = None
    node: str | None = None
    resource_type: str
    resource_id: str
    vmid: int | None = None
    storage_id: str | None = None


class RequestOptions(StrictBaseModel):
    dry_run: bool = False
    explain_plan: bool = False
    include_impact_analysis: bool = False
    idempotency_key: str | None = None
    approval_token: str | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)


class PaginationInput(StrictBaseModel):
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = None


class PaginationOutput(StrictBaseModel):
    next_cursor: str | None = None
    has_more: bool = False


class ToolRequest(StrictBaseModel):
    request_id: str = Field(default_factory=_new_request_id)
    correlation_id: str = ""
    actor: Actor
    target: Target
    parameters: dict[str, object] = Field(default_factory=dict)
    options: RequestOptions = Field(default_factory=RequestOptions)
    pagination: PaginationInput | None = None

    @model_validator(mode="after")
    def _default_correlation_id(self) -> Self:
        if not self.correlation_id:
            self.correlation_id = self.request_id

        return self


class Risk(StrictBaseModel):
    level: RiskLevel
    score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    dangerous_operation: bool = False


class PolicyDecision(StrictBaseModel):
    decision: PolicyDecisionValue
    matched_rules: list[str] = Field(default_factory=list)
    reason: str | None = None


class ApprovalInfo(StrictBaseModel):
    required: bool = False
    approval_request_id: str | None = None
    expires_at: str | None = None


class ResourceRef(StrictBaseModel):
    type: str
    id: str
    node: str | None = None
    name: str | None = None


def _empty_resource_refs() -> list[ResourceRef]:
    return []


class Impact(StrictBaseModel):
    affected_resources: list[ResourceRef] = Field(default_factory=_empty_resource_refs)
    dependencies: list[ResourceRef] = Field(default_factory=_empty_resource_refs)
    estimated_downtime_seconds: int | None = Field(default=None, ge=0)
    data_loss_possible: bool = False
    network_disruption_possible: bool = False
    quorum_risk: bool = False
    rollback_available: bool = False
    rollback_suggestions: list[str] = Field(default_factory=list)


class ApprovalRequest(StrictBaseModel):
    approval_request_id: str
    operation: str
    target_hash: str
    input_hash: str
    actor: Actor
    risk: Risk
    impact: Impact
    expires_at: str
    status: ApprovalRequestStatus


class IdempotencyScope(StrictBaseModel):
    tenant_id: str
    actor: Actor
    tool_name: str
    target: Target
    input_hash: str
    idempotency_key: str


class AuditRef(StrictBaseModel):
    event_id: str
    recorded: bool


class ToolResponse(StrictBaseModel):
    request_id: str
    correlation_id: str
    status: Literal["success"] = "success"
    dry_run: bool
    risk: Risk
    policy: PolicyDecision
    approval: ApprovalInfo
    impact: Impact
    result: object
    warnings: list[str] = Field(default_factory=list)
    rollback_suggestions: list[str] = Field(default_factory=list)
    audit: AuditRef
    pagination: PaginationOutput | None = None


class ToolError(StrictBaseModel):
    code: ErrorCode
    message: str
    details: dict[str, object] = Field(default_factory=dict)
    retryable: bool = False


class ToolErrorResponse(StrictBaseModel):
    request_id: str
    correlation_id: str
    status: Literal["error"] = "error"
    error: ToolError
    audit: AuditRef
