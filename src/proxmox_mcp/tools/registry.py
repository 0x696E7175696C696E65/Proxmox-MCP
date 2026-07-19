from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from time import perf_counter
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model

if TYPE_CHECKING:
    from fastmcp.tools import FunctionTool

from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.observability import MetricsSink, MetricStatus, TraceSpan, structured_log
from proxmox_mcp.reliability import request_fingerprint
from proxmox_mcp.schemas.envelope import (
    Actor,
    ApprovalInfo,
    AuditRef,
    ErrorCode,
    Impact,
    PolicyDecision,
    RequestOptions,
    ResourceRef,
    Risk,
    RiskLevel,
    Target,
    ToolError,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.security.redaction import sanitize_for_security_boundary
from proxmox_mcp.tools.context import ToolExecutionContext

ConnectorType = Literal["internal", "proxmox_api", "ssh", "hybrid"]
ToolHandler = Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]
FastMCPRequest = ToolRequest | dict[str, object] | None
FastMCPTool = Callable[[FastMCPRequest], Awaitable[ToolResponse | ToolErrorResponse]]
ContextFactory = Callable[[ToolRequest], ToolExecutionContext]
GuardDecisionValue = Literal["allowed", "denied", "requires_approval"]
ObservabilityLogSink = Callable[[str], None]

_RISK_SCORES: dict[RiskLevel, int] = {
    "low": 10,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


class FastMCPToolRegistrar(Protocol):
    def add_tool(self, tool: FunctionTool) -> object: ...


class ToolDefinition(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    category: str = Field(min_length=1)
    permission: str = Field(min_length=1)
    risk: RiskLevel
    dry_run: bool
    approval_default: bool
    connector: ConnectorType
    handler: ToolHandler
    parameters_model: type[BaseModel] | None = None
    result_model: type[BaseModel] | None = None


class ToolSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    parameters_schema: dict[str, object] | None = None
    result_schema: dict[str, object] | None = None


class ToolExecutionError(RuntimeError):
    def __init__(
        self,
        *,
        error_code: ErrorCode,
        message: str,
        retryable: bool = False,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code: ErrorCode = error_code
        self.retryable: bool = retryable
        self.details: dict[str, object] = {} if details is None else details


class ToolGuardDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: GuardDecisionValue
    error_code: ErrorCode | None = None
    message: str | None = None
    details: dict[str, object] = Field(default_factory=dict)
    risk: Risk | None = None
    policy: PolicyDecision | None = None
    approval: ApprovalInfo | None = None
    impact: Impact | None = None

    @classmethod
    def allowed(
        cls,
        *,
        risk: Risk | None = None,
        policy: PolicyDecision | None = None,
        approval: ApprovalInfo | None = None,
        impact: Impact | None = None,
    ) -> ToolGuardDecision:
        return cls(
            decision="allowed",
            risk=risk,
            policy=policy,
            approval=approval,
            impact=impact,
        )

    @classmethod
    def denied(
        cls,
        *,
        error_code: ErrorCode = "POLICY_DENIED",
        message: str = "Tool execution denied",
        details: dict[str, object] | None = None,
        risk: Risk | None = None,
        policy: PolicyDecision | None = None,
        approval: ApprovalInfo | None = None,
        impact: Impact | None = None,
    ) -> ToolGuardDecision:
        return cls(
            decision="denied",
            error_code=error_code,
            message=message,
            details={} if details is None else details,
            risk=risk,
            policy=policy,
            approval=approval,
            impact=impact,
        )

    @classmethod
    def requires_approval(
        cls,
        *,
        message: str = "Tool execution requires approval",
        approval_request_id: str | None = None,
        risk: Risk | None = None,
        policy: PolicyDecision | None = None,
        approval: ApprovalInfo | None = None,
        impact: Impact | None = None,
    ) -> ToolGuardDecision:
        details: dict[str, object] = {}
        if approval_request_id is not None:
            details["approval_request_id"] = approval_request_id

        approval_info = ApprovalInfo(required=True, approval_request_id=approval_request_id)
        if approval is not None:
            approval_info = approval

        return cls(
            decision="requires_approval",
            error_code="APPROVAL_REQUIRED",
            message=message,
            details=details,
            risk=risk,
            policy=policy,
            approval=approval_info,
            impact=impact,
        )


class ToolExecutionGuard(Protocol):
    def evaluate(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> Awaitable[ToolGuardDecision]: ...


class ToolRegistry:
    def __init__(
        self,
        *,
        guard: ToolExecutionGuard | None = None,
        metrics_sink: MetricsSink | None = None,
        log_sink: ObservabilityLogSink | None = None,
    ) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        self._guard = guard
        self._metrics_sink = metrics_sink
        self._log_sink = log_sink

    def register(self, definition: ToolDefinition) -> ToolDefinition:
        if definition.name in self._definitions:
            raise ValueError(f"Tool {definition.name!r} is already registered")

        self._definitions[definition.name] = definition
        return definition

    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._definitions.values())

    def get(self, name: str) -> ToolDefinition:
        return self._definitions[name]

    def schemas(self) -> tuple[ToolSchema, ...]:
        return tuple(
            ToolSchema(
                name=definition.name,
                parameters_schema=None
                if definition.parameters_model is None
                else definition.parameters_model.model_json_schema(),
                result_schema=None
                if definition.result_model is None
                else definition.result_model.model_json_schema(),
            )
            for definition in self.definitions()
        )

    async def execute(
        self,
        name: str,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolResponse | ToolErrorResponse:
        definition = self.get(name)
        started_at = perf_counter()
        trace_span = TraceSpan.start(
            "tool.execute",
            tool_name=definition.name,
            connector=definition.connector,
            correlation_id=request.correlation_id,
        )
        if self._metrics_sink is not None or self._log_sink is not None:
            context.audit_metadata.setdefault("trace_id", trace_span.trace_id)
            context.audit_metadata.setdefault("span_id", trace_span.span_id)
        await self._write_audit_event(
            definition,
            request,
            context,
            "tool.execution.started",
            "started",
        )
        options_error = await self._validate_request_options(definition, request, context)
        if options_error is not None:
            self._record_observability(
                definition,
                request,
                trace_span,
                "error",
                started_at,
                options_error.audit.event_id,
                error_code=options_error.error.code,
            )
            return options_error

        parameter_error = await self._validate_parameters(definition, request, context)
        if parameter_error is not None:
            self._record_observability(
                definition,
                request,
                trace_span,
                "error",
                started_at,
                parameter_error.audit.event_id,
                error_code=parameter_error.error.code,
            )
            return parameter_error

        guard_decision = await self._evaluate_guard(definition, request, context)
        if guard_decision.decision != "allowed":
            error_code = guard_decision.error_code or "POLICY_DENIED"
            denied_event = await self._write_audit_event(
                definition,
                request,
                context,
                "tool.execution.finished",
                "denied",
                error_code=error_code,
            )
            self._record_observability(
                definition,
                request,
                trace_span,
                "denied",
                started_at,
                denied_event.event_id,
                error_code=error_code,
            )
            return ToolErrorResponse(
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                error=ToolError(
                    code=error_code,
                    message=guard_decision.message or "Tool execution denied",
                    details=self._sanitize_details(guard_decision.details),
                    retryable=False,
                ),
                audit=AuditRef(event_id=denied_event.event_id, recorded=True),
            )

        idempotency_key = request.options.idempotency_key
        idempotency_fingerprint: str | None = None
        if (
            context.idempotency_store is not None
            and idempotency_key is not None
            and not request.options.dry_run
        ):
            idempotency_fingerprint = request_fingerprint(
                {
                    "tool": definition.name,
                    "actor": request.actor.model_dump(mode="json"),
                    "target": request.target.model_dump(mode="json"),
                    "parameters": request.parameters,
                }
            )
            claim = await context.idempotency_store.begin(
                idempotency_key=idempotency_key,
                request_fingerprint=idempotency_fingerprint,
            )
            if not claim.acquired:
                error_event = await self._write_audit_event(
                    definition,
                    request,
                    context,
                    "tool.execution.finished",
                    "error",
                    error_code="CONFLICT",
                )
                self._record_observability(
                    definition,
                    request,
                    trace_span,
                    "error",
                    started_at,
                    error_event.event_id,
                    error_code="CONFLICT",
                )
                return ToolErrorResponse(
                    request_id=request.request_id,
                    correlation_id=request.correlation_id,
                    error=ToolError(
                        code="CONFLICT",
                        message="Idempotency key is already in use",
                        details={"reason": claim.reason or "duplicate"},
                        retryable=False,
                    ),
                    audit=AuditRef(event_id=error_event.event_id, recorded=True),
                )

        try:
            data = await definition.handler(request, context)
            data = self._validate_result(definition, data)
        except ToolExecutionError as exc:
            error_event = await self._write_audit_event(
                definition,
                request,
                context,
                "tool.execution.finished",
                "error",
                error_code=exc.error_code,
            )
            self._record_observability(
                definition,
                request,
                trace_span,
                "error",
                started_at,
                error_event.event_id,
                error_code=exc.error_code,
            )
            await self._complete_idempotency(
                context,
                idempotency_key=idempotency_key,
                request_fingerprint=idempotency_fingerprint,
                result_status="error",
                error_code=exc.error_code,
            )
            return ToolErrorResponse(
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                error=ToolError(
                    code=exc.error_code,
                    message=str(exc),
                    details=self._sanitize_details(exc.details),
                    retryable=exc.retryable,
                ),
                audit=AuditRef(event_id=error_event.event_id, recorded=True),
            )
        except ValidationError:
            error_event = await self._write_audit_event(
                definition,
                request,
                context,
                "tool.execution.finished",
                "error",
                error_code="INTERNAL_ERROR",
            )
            self._record_observability(
                definition,
                request,
                trace_span,
                "error",
                started_at,
                error_event.event_id,
                error_code="INTERNAL_ERROR",
            )
            await self._complete_idempotency(
                context,
                idempotency_key=idempotency_key,
                request_fingerprint=idempotency_fingerprint,
                result_status="error",
                error_code="INTERNAL_ERROR",
            )
            return ToolErrorResponse(
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                error=ToolError(
                    code="INTERNAL_ERROR",
                    message="Tool execution failed",
                    retryable=False,
                ),
                audit=AuditRef(event_id=error_event.event_id, recorded=True),
            )
        except Exception:
            error_event = await self._write_audit_event(
                definition,
                request,
                context,
                "tool.execution.finished",
                "error",
                error_code="INTERNAL_ERROR",
            )
            self._record_observability(
                definition,
                request,
                trace_span,
                "error",
                started_at,
                error_event.event_id,
                error_code="INTERNAL_ERROR",
            )
            await self._complete_idempotency(
                context,
                idempotency_key=idempotency_key,
                request_fingerprint=idempotency_fingerprint,
                result_status="error",
                error_code="INTERNAL_ERROR",
            )
            return ToolErrorResponse(
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                error=ToolError(
                    code="INTERNAL_ERROR",
                    message="Tool execution failed",
                    retryable=False,
                ),
                audit=AuditRef(event_id=error_event.event_id, recorded=True),
            )

        success_event = await self._write_audit_event(
            definition,
            request,
            context,
            "tool.execution.finished",
            "success",
        )
        self._record_observability(
            definition,
            request,
            trace_span,
            "success",
            started_at,
            success_event.event_id,
        )
        await self._complete_idempotency(
            context,
            idempotency_key=idempotency_key,
            request_fingerprint=idempotency_fingerprint,
            result_status="success",
        )
        impact = guard_decision.impact or self._default_impact(request)
        return ToolResponse(
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            dry_run=request.options.dry_run,
            risk=guard_decision.risk or self._default_risk(definition),
            policy=guard_decision.policy or self._default_policy(definition),
            approval=guard_decision.approval or self._default_approval(definition),
            impact=impact,
            result=data,
            rollback_suggestions=impact.rollback_suggestions,
            audit=AuditRef(event_id=success_event.event_id, recorded=True),
        )

    def register_with_fastmcp(
        self,
        app: FastMCPToolRegistrar,
        context_factory: ContextFactory,
    ) -> None:
        from fastmcp.tools import FunctionTool

        for definition in self.definitions():
            app.add_tool(
                FunctionTool(
                    name=definition.name,
                    description=definition.description,
                    parameters=self.fastmcp_input_schema(definition),
                    output_schema=None,
                    fn=self._build_fastmcp_handler(definition, context_factory),
                )
            )

    def fastmcp_input_schema(self, definition: ToolDefinition) -> dict[str, object]:
        """Build the per-tool MCP input schema an agent sees.

        The surface is ``{target, parameters, options}`` where ``parameters`` is the
        tool's own parameter model, so the schema documents the exact keys a tool
        needs instead of an opaque request envelope. ``actor`` is derived from the
        authenticated session and is intentionally not part of the agent surface.
        """
        parameters_type: object = (
            definition.parameters_model
            if definition.parameters_model is not None
            else dict[str, object]
        )
        target_field: tuple[object, object] = (
            (Target | None, None) if definition.connector == "internal" else (Target, ...)
        )
        input_model = create_model(
            f"{self._pascal_case(definition.name)}Input",
            __config__=ConfigDict(extra="forbid"),
            **cast(
                dict[str, Any],
                {
                    "target": target_field,
                    "parameters": (parameters_type, Field(default_factory=dict)),
                    "options": (RequestOptions, Field(default_factory=RequestOptions)),
                },
            ),
        )
        return input_model.model_json_schema()

    @staticmethod
    def _pascal_case(value: str) -> str:
        return "".join(part.capitalize() for part in re.split(r"[._]", value) if part)

    async def _complete_idempotency(
        self,
        context: ToolExecutionContext,
        *,
        idempotency_key: str | None,
        request_fingerprint: str | None,
        result_status: str,
        error_code: str | None = None,
    ) -> None:
        if (
            context.idempotency_store is None
            or idempotency_key is None
            or request_fingerprint is None
        ):
            return
        await context.idempotency_store.complete(
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
            result_status=result_status,
            error_code=error_code,
        )

    def _build_fastmcp_handler(
        self,
        definition: ToolDefinition,
        context_factory: ContextFactory,
    ) -> FastMCPTool:
        async def registered_tool(
            **kwargs: object,
        ) -> ToolResponse | ToolErrorResponse:
            try:
                tool_request = self._coerce_request(definition, kwargs)
            except Exception as exc:
                request_id = self._new_validation_request().request_id
                return ToolErrorResponse(
                    request_id=request_id,
                    correlation_id=request_id,
                    error=ToolError(
                        code="INVALID_REQUEST",
                        message=str(exc),
                        retryable=False,
                    ),
                    audit=AuditRef(event_id="", recorded=False),
                )

            context = context_factory(tool_request)
            return await self.execute(definition.name, tool_request, context)

        return cast(FastMCPTool, registered_tool)

    def _coerce_request(
        self,
        definition: ToolDefinition,
        request: FastMCPRequest,
    ) -> ToolRequest:
        if request is None:
            return self._default_request(definition)

        if isinstance(request, ToolRequest):
            return request

        normalized_request = {
            key: value for key, value in dict(request).items() if value is not None
        }
        if "actor" not in normalized_request:
            normalized_request["actor"] = {"user_id": "mcp-client", "agent_id": "mcp-client"}
        if "target" not in normalized_request and definition.connector == "internal":
            normalized_request["target"] = {
                "resource_type": definition.category,
                "resource_id": definition.name,
            }
        if definition.dry_run:
            options = normalized_request.get("options")
            if options is None:
                normalized_request["options"] = {"dry_run": True}
            elif isinstance(options, dict) and "dry_run" not in options:
                normalized_request["options"] = {**options, "dry_run": True}

        return ToolRequest.model_validate(normalized_request)

    def _default_request(self, definition: ToolDefinition) -> ToolRequest:
        if definition.connector != "internal":
            raise ValueError("Tool request is required for non-internal tools")

        return ToolRequest(
            actor=Actor(user_id="system", agent_id="system"),
            target=Target(resource_type=definition.category, resource_id=definition.name),
            options=RequestOptions(dry_run=definition.dry_run),
        )

    def _new_validation_request(self) -> ToolRequest:
        return ToolRequest(
            actor=Actor(user_id="system", agent_id="system"),
            target=Target(resource_type="internal", resource_id="validation"),
        )

    def _record_observability(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        trace_span: TraceSpan,
        status: MetricStatus,
        started_at: float,
        audit_event_id: str,
        *,
        error_code: str | None = None,
    ) -> None:
        duration_ms = max(0, int((perf_counter() - started_at) * 1000))
        if self._metrics_sink is not None:
            self._metrics_sink.record_tool_invocation(
                tool_name=definition.name,
                connector=definition.connector,
                status=status,
                duration_ms=duration_ms,
            )

        if self._log_sink is not None:
            self._log_sink(
                structured_log(
                    event="tool.execution.finished",
                    level="error" if status == "error" else "info",
                    tool_name=definition.name,
                    connector=definition.connector,
                    status=status,
                    duration_ms=duration_ms,
                    request_id=request.request_id,
                    correlation_id=request.correlation_id,
                    audit_event_id=audit_event_id,
                    trace_id=trace_span.trace_id,
                    span_id=trace_span.span_id,
                    error_code=error_code,
                )
            )

    async def _write_audit_event(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
        event_type: str,
        result_status: Literal["started", "success", "error", "denied"],
        *,
        error_code: str | None = None,
    ) -> AuditEvent:
        actor_user_id, actor_agent_id, tenant_id = self._audit_identity(
            definition,
            request,
            context,
        )
        event = AuditEvent(
            event_type=event_type,
            correlation_id=request.correlation_id,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_agent_id=actor_agent_id,
            tool_name=definition.name,
            operation=definition.permission,
            target=AuditTarget(
                cluster_id=request.target.cluster,
                node_id=request.target.node,
                resource_type=request.target.resource_type,
                resource_id=request.target.resource_id,
            ),
            result_status=result_status,
            error_code=error_code,
            metadata={
                "request_id": request.request_id,
                "tenant_id": tenant_id,
                "connector": definition.connector,
                "risk": definition.risk,
                "dry_run": request.options.dry_run,
                **self._sanitize_metadata(context.audit_metadata),
            },
        )
        await context.audit_writer.write(event)
        return event

    def _sanitize_details(self, details: dict[str, object]) -> dict[str, object]:
        sanitized = sanitize_for_security_boundary(details)
        if not isinstance(sanitized, dict):
            return {}
        return cast(dict[str, object], sanitized)

    def _sanitize_metadata(self, metadata: dict[str, object]) -> dict[str, object]:
        sanitized = sanitize_for_security_boundary(metadata)
        if not isinstance(sanitized, dict):
            return {}
        return cast(dict[str, object], sanitized)

    def _audit_identity(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> tuple[str, str, str | None]:
        if definition.connector == "internal":
            return request.actor.user_id, request.actor.agent_id, request.actor.tenant_id

        session = context.authenticated_session
        if (
            session is not None
            and session.status == "active"
            and session.expires_at > datetime.now(UTC)
        ):
            return session.identity.user_id, session.identity.agent_id, session.identity.tenant_id

        return "unauthenticated", "unauthenticated", None

    async def _validate_parameters(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolErrorResponse | None:
        if definition.parameters_model is None:
            return None

        try:
            validated = definition.parameters_model.model_validate(request.parameters)
        except ValidationError:
            error_event = await self._write_audit_event(
                definition,
                request,
                context,
                "tool.execution.finished",
                "error",
                error_code="INVALID_REQUEST",
            )
            return ToolErrorResponse(
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                error=ToolError(
                    code="INVALID_REQUEST",
                    message="Tool request parameters failed validation",
                    retryable=False,
                ),
                audit=AuditRef(event_id=error_event.event_id, recorded=True),
            )

        request.parameters = validated.model_dump(mode="json", exclude_none=True)
        return None

    async def _validate_request_options(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolErrorResponse | None:
        if definition.connector == "internal" or definition.dry_run or not request.options.dry_run:
            return None

        error_event = await self._write_audit_event(
            definition,
            request,
            context,
            "tool.execution.finished",
            "error",
            error_code="INVALID_REQUEST",
        )
        return ToolErrorResponse(
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            error=ToolError(
                code="INVALID_REQUEST",
                message="Tool does not support dry-run requests",
                retryable=False,
            ),
            audit=AuditRef(event_id=error_event.event_id, recorded=True),
        )

    def _validate_result(self, definition: ToolDefinition, data: object) -> object:
        if definition.result_model is None:
            return data

        return definition.result_model.model_validate(data).model_dump(mode="json")

    async def _evaluate_guard(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolGuardDecision:
        if self._guard is None:
            if definition.connector != "internal":
                return ToolGuardDecision.denied(
                    error_code="AUTHENTICATION_REQUIRED",
                    message="Security guard required for non-internal tool execution",
                )

            if definition.approval_default:
                return ToolGuardDecision.requires_approval()

            return ToolGuardDecision.allowed()

        return await self._guard.evaluate(definition, request, context)

    def _default_risk(self, definition: ToolDefinition) -> Risk:
        return Risk(
            level=definition.risk,
            score=_RISK_SCORES[definition.risk],
            reasons=[definition.permission],
            dangerous_operation=definition.risk in ("high", "critical"),
        )

    def _default_policy(self, definition: ToolDefinition) -> PolicyDecision:
        return PolicyDecision(
            decision="requires_approval" if definition.approval_default else "allow",
            matched_rules=[definition.permission] if definition.approval_default else [],
        )

    def _default_approval(self, definition: ToolDefinition) -> ApprovalInfo:
        return ApprovalInfo(required=definition.approval_default)

    def _default_impact(self, request: ToolRequest) -> Impact:
        return Impact(
            affected_resources=[
                ResourceRef(
                    type=request.target.resource_type,
                    id=request.target.resource_id,
                    node=request.target.node,
                )
            ]
        )
