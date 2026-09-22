from __future__ import annotations

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.reliability import CircuitBreaker, CircuitOpenError, RetryPolicy
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
)
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolGuardDecision, ToolRegistry


def test_circuit_breaker_opens_after_threshold() -> None:
    breaker = CircuitBreaker(failure_threshold=2, recovery_seconds=60)

    breaker.record_failure()
    breaker.record_failure()

    with pytest.raises(CircuitOpenError):
        breaker.before_call()


async def test_retry_policy_retries_until_success() -> None:
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise RuntimeError("temporary")
        return "ok"

    result = await RetryPolicy(attempts=3, backoff_seconds=0).run(operation)

    assert result == "ok"
    assert attempts == 2


async def test_registry_maps_circuit_open_to_structured_retryable_error() -> None:
    class AllowAllGuard:
        async def evaluate(self, *_args: object, **_kwargs: object) -> ToolGuardDecision:
            return ToolGuardDecision.allowed()

    async def raising_handler(_request: ToolRequest, _context: ToolExecutionContext) -> object:
        raise CircuitOpenError("Circuit is open")

    writer = InMemoryAuditWriter()
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1"),
        target=Target(resource_type="cluster", resource_id="lab"),
        options=RequestOptions(dry_run=True),
    )
    registry = ToolRegistry(guard=AllowAllGuard())
    registry.register(
        ToolDefinition(
            name="list_nodes",
            description="List nodes",
            category="cluster",
            permission="cluster.read",
            risk="low",
            dry_run=True,
            approval_default=False,
            connector="proxmox_api",
            handler=raising_handler,
        )
    )

    response = await registry.execute(
        "list_nodes",
        request,
        ToolExecutionContext(
            request=request,
            settings=Settings(environment="test"),
            audit_writer=writer,
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "CIRCUIT_OPEN"
    assert response.error.retryable is True
    assert [event.result_status for event in writer.events] == ["started", "error"]
