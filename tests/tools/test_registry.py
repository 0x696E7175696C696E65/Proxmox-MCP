import json
from collections.abc import Awaitable, Callable
from typing import cast

import pytest
from pydantic import BaseModel, ConfigDict

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.observability import InMemoryMetricsRegistry
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import (
    FastMCPRequest,
    ToolDefinition,
    ToolGuardDecision,
    ToolRegistry,
)

RegisteredTool = Callable[[FastMCPRequest], Awaitable[ToolResponse | ToolErrorResponse]]


class RecordingFastMCP:
    def __init__(self) -> None:
        self.tools: dict[str, RegisteredTool] = {}

    def tool(self, *, name: str) -> Callable[[RegisteredTool], RegisteredTool]:
        def decorate(handler: RegisteredTool) -> RegisteredTool:
            self.tools[name] = handler
            return handler

        return decorate


class FakeIdempotencyStore:
    def __init__(self) -> None:
        self.claimed: set[str] = set()
        self.completed: list[dict[str, object]] = []

    async def begin(
        self,
        *,
        idempotency_key: str,
        request_fingerprint: str,
        ttl_seconds: int = 3600,
    ):
        _ = request_fingerprint, ttl_seconds
        if idempotency_key in self.claimed:
            from proxmox_mcp.reliability import IdempotencyClaim

            return IdempotencyClaim(acquired=False, reason="completed")
        self.claimed.add(idempotency_key)
        from proxmox_mcp.reliability import IdempotencyClaim

        return IdempotencyClaim(acquired=True)

    async def complete(
        self,
        *,
        idempotency_key: str,
        request_fingerprint: str,
        result_status: str,
        error_code: str | None = None,
    ) -> None:
        self.completed.append(
            {
                "idempotency_key": idempotency_key,
                "request_fingerprint": request_fingerprint,
                "result_status": result_status,
                "error_code": error_code,
            }
        )


def make_context(
    request: ToolRequest | None = None,
    writer: InMemoryAuditWriter | None = None,
) -> ToolExecutionContext:
    request = make_request() if request is None else request
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter() if writer is None else writer,
    )


def make_request() -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(cluster="prod-pve", node="pve-1", resource_type="vm", resource_id="100"),
        parameters={"value": "ok"},
        options=RequestOptions(dry_run=True),
    )


async def echo_handler(
    request: ToolRequest,
    context: ToolExecutionContext,
) -> dict[str, object]:
    return {
        "value": request.parameters["value"],
        "environment": context.settings.environment,
        "dry_run": request.options.dry_run,
        "context_request_id": context.request_id,
    }


def make_definition(name: str = "example.echo") -> ToolDefinition:
    return ToolDefinition(
        name=name,
        category="example",
        permission="example.echo",
        risk="low",
        dry_run=True,
        approval_default=False,
        connector="internal",
        handler=echo_handler,
    )


def test_context_properties_are_derived_from_request() -> None:
    request = make_request()
    context = make_context(request)

    assert context.request_id == request.request_id
    assert context.correlation_id == request.correlation_id
    assert context.actor is request.actor
    assert context.target is request.target

    request.correlation_id = "corr_changed"

    assert context.correlation_id == "corr_changed"


def test_registry_rejects_duplicate_tool_names() -> None:
    registry = ToolRegistry()
    registry.register(make_definition())

    with pytest.raises(ValueError, match="already registered"):
        registry.register(make_definition())


def test_registry_exposes_registered_metadata_without_unimplemented_tools() -> None:
    registry = ToolRegistry()
    registry.register(make_definition("example.echo"))

    definitions = registry.definitions()

    assert [definition.name for definition in definitions] == ["example.echo"]
    assert registry.get("example.echo").permission == "example.echo"
    assert registry.get("example.echo").risk == "low"
    assert registry.get("example.echo").connector == "internal"

    with pytest.raises(KeyError):
        registry.get("unimplemented.tool")


async def test_registry_executes_async_handlers_and_wraps_success_envelope() -> None:
    registry = ToolRegistry()
    registry.register(make_definition())
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("example.echo", request, make_context(request, writer))

    assert isinstance(response, ToolResponse)
    assert response.request_id == request.request_id
    assert response.correlation_id == request.correlation_id
    assert response.status == "success"
    assert response.dry_run is True
    assert response.result == {
        "value": "ok",
        "environment": "test",
        "dry_run": True,
        "context_request_id": request.request_id,
    }
    assert response.risk.level == "low"
    assert response.risk.score == 10
    assert response.risk.reasons == ["example.echo"]
    assert response.policy.decision == "allow"
    assert response.approval.required is False
    assert response.audit.recorded is True
    assert [event.result_status for event in writer.events] == ["started", "success"]
    assert writer.events[0].operation == "example.echo"
    assert writer.events[0].target.resource_type == "vm"
    assert [event.tenant_id for event in writer.events] == ["tenant_1", "tenant_1"]
    assert writer.events[0].metadata["tenant_id"] == "tenant_1"


async def test_registry_blocks_duplicate_live_idempotency_key() -> None:
    store = FakeIdempotencyStore()
    handler_calls = 0

    async def live_handler(
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> dict[str, object]:
        nonlocal handler_calls
        _ = request, context
        handler_calls += 1
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="example.live",
            category="example",
            permission="example.live",
            risk="medium",
            dry_run=True,
            approval_default=False,
            connector="internal",
            handler=live_handler,
        )
    )
    request = make_request()
    request.options.dry_run = False
    request.options.idempotency_key = "idem-1"
    writer = InMemoryAuditWriter()
    context = make_context(request, writer)
    context = ToolExecutionContext(
        request=request,
        settings=context.settings,
        audit_writer=context.audit_writer,
        idempotency_store=store,
    )

    first = await registry.execute("example.live", request, context)
    second = await registry.execute("example.live", request, context)

    assert isinstance(first, ToolResponse)
    assert isinstance(second, ToolErrorResponse)
    assert second.error.code == "CONFLICT"
    assert handler_calls == 1
    assert store.completed[0]["result_status"] == "success"


async def test_registry_records_metrics_logs_and_trace_correlation() -> None:
    metrics = InMemoryMetricsRegistry()
    logs: list[str] = []
    registry = ToolRegistry(metrics_sink=metrics, log_sink=logs.append)
    registry.register(make_definition())
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("example.echo", request, make_context(request, writer))

    assert isinstance(response, ToolResponse)
    assert len(metrics.invocations) == 1
    invocation = metrics.invocations[0]
    assert invocation.tool_name == "example.echo"
    assert invocation.connector == "internal"
    assert invocation.status == "success"

    assert len(logs) == 1
    log_payload = cast(dict[str, object], json.loads(logs[0]))
    assert log_payload["tool_name"] == "example.echo"
    assert log_payload["status"] == "success"
    assert log_payload["correlation_id"] == request.correlation_id
    assert log_payload["audit_event_id"] == response.audit.event_id

    assert writer.events[-1].metadata["trace_id"] == log_payload["trace_id"]
    assert writer.events[-1].metadata["span_id"] == log_payload["span_id"]


async def test_registry_wraps_handler_errors_in_error_envelope() -> None:
    async def failing_handler(
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> dict[str, object]:
        raise RuntimeError(f"cannot execute {request.parameters['value']}")

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="example.failing",
            category="example",
            permission="example.failing",
            risk="medium",
            dry_run=False,
            approval_default=False,
            connector="internal",
            handler=failing_handler,
        )
    )
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("example.failing", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.request_id == request.request_id
    assert response.correlation_id == request.correlation_id
    assert response.status == "error"
    assert response.error.code == "INTERNAL_ERROR"
    assert response.error.message == "Tool execution failed"
    assert response.audit.recorded is True
    assert [event.result_status for event in writer.events] == ["started", "error"]
    assert writer.events[-1].error_code == "INTERNAL_ERROR"
    assert writer.events[-1].tool_name == "example.failing"


async def test_registry_registers_definitions_with_fastmcp_style_apps() -> None:
    registry = ToolRegistry()
    registry.register(make_definition())
    app = RecordingFastMCP()

    registry.register_with_fastmcp(app, make_context)

    assert list(app.tools) == ["example.echo"]
    assert "unimplemented.tool" not in app.tools
    response = await app.tools["example.echo"](make_request())

    assert isinstance(response, ToolResponse)
    assert response.status == "success"
    result = cast(dict[str, object], response.result)
    assert result["value"] == "ok"


async def test_registry_guard_can_require_approval_without_executing_handler() -> None:
    handler_called = False

    async def guarded_handler(
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> dict[str, object]:
        nonlocal handler_called
        handler_called = True
        return {"value": request.parameters["value"], "context_id": context.request_id}

    class ApprovalRequiredGuard:
        async def evaluate(
            self,
            definition: ToolDefinition,
            request: ToolRequest,
            context: ToolExecutionContext,
        ) -> ToolGuardDecision:
            return ToolGuardDecision.requires_approval(
                message=f"{definition.name} needs approval for {request.target.resource_id}",
                approval_request_id="apr_1",
            )

    registry = ToolRegistry(guard=ApprovalRequiredGuard())
    registry.register(
        ToolDefinition(
            name="example.guarded",
            category="example",
            permission="example.guarded",
            risk="critical",
            dry_run=False,
            approval_default=True,
            connector="internal",
            handler=guarded_handler,
        )
    )
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("example.guarded", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "APPROVAL_REQUIRED"
    assert response.error.details == {"approval_request_id": "apr_1"}
    assert handler_called is False
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_registry_requires_guard_for_non_internal_tools() -> None:
    handler_called = False

    async def guarded_handler(
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> dict[str, object]:
        nonlocal handler_called
        handler_called = True
        return {"value": request.parameters["value"]}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="vm.status",
            category="vm",
            permission="vm.read",
            risk="low",
            dry_run=True,
            approval_default=False,
            connector="proxmox_api",
            handler=guarded_handler,
        )
    )
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("vm.status", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "AUTHENTICATION_REQUIRED"
    assert handler_called is False
    assert [event.result_status for event in writer.events] == ["started", "denied"]
    assert [event.actor_user_id for event in writer.events] == [
        "unauthenticated",
        "unauthenticated",
    ]
    assert [event.tenant_id for event in writer.events] == [None, None]


async def test_registry_blocks_approval_default_without_guard() -> None:
    handler_called = False

    async def guarded_handler(
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> dict[str, object]:
        nonlocal handler_called
        handler_called = True
        return {"value": request.parameters["value"]}

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="internal.guarded",
            category="internal",
            permission="internal.guarded",
            risk="high",
            dry_run=False,
            approval_default=True,
            connector="internal",
            handler=guarded_handler,
        )
    )
    request = make_request()
    writer = InMemoryAuditWriter()

    response = await registry.execute("internal.guarded", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "APPROVAL_REQUIRED"
    assert handler_called is False
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_registry_validates_parameters_before_guard_evaluation() -> None:
    class ExampleParameters(BaseModel):
        model_config = ConfigDict(extra="forbid")

        value: str = "defaulted"

    captured_parameters: dict[str, object] | None = None

    class RecordingGuard:
        async def evaluate(
            self,
            definition: ToolDefinition,
            request: ToolRequest,
            context: ToolExecutionContext,
        ) -> ToolGuardDecision:
            nonlocal captured_parameters
            captured_parameters = request.parameters
            return ToolGuardDecision.allowed()

    registry = ToolRegistry(guard=RecordingGuard())
    registry.register(
        ToolDefinition(
            name="example.validated",
            category="example",
            permission="example.validated",
            risk="low",
            dry_run=True,
            approval_default=False,
            connector="internal",
            handler=echo_handler,
            parameters_model=ExampleParameters,
        )
    )
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(resource_type="example", resource_id="validated"),
        parameters={},
        options=RequestOptions(dry_run=True),
    )

    response = await registry.execute(
        "example.validated",
        request,
        make_context(request, InMemoryAuditWriter()),
    )

    assert isinstance(response, ToolResponse)
    assert captured_parameters == {"value": "defaulted"}
