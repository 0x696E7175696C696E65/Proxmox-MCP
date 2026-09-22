from __future__ import annotations

import pytest

from proxmox_mcp.config import Settings
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest
from proxmox_mcp.server.health import StaticDependencyChecker, build_readiness_payload
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.internal import HEALTH_CHECK_DEFINITION
from proxmox_mcp.tools.registry import ToolRegistry


async def test_readiness_fails_closed_during_required_dependency_outage() -> None:
    payload = await build_readiness_payload(
        Settings(environment="test"),
        {
            "postgresql": StaticDependencyChecker(
                name="postgresql",
                required=True,
                status="unavailable",
                detail="simulated outage",
            ),
            "redis": StaticDependencyChecker(
                name="redis",
                required=True,
                status="ok",
                detail="ping succeeded",
            ),
        },
    )

    assert payload.status == "not_ready"
    assert payload.dependencies["postgresql"].detail == "simulated outage"


async def test_audit_write_failure_returns_structured_error_without_handler_success() -> None:
    class FailingAuditWriter:
        async def write(self, event: object) -> None:
            _ = event
            raise RuntimeError("audit sink unavailable")

    registry = ToolRegistry()
    registry.register(HEALTH_CHECK_DEFINITION)
    request = ToolRequest(
        actor=Actor(user_id="system", agent_id="system"),
        target=Target(resource_type="internal", resource_id="health"),
        options=RequestOptions(dry_run=True),
    )

    with pytest.raises(RuntimeError, match="audit sink unavailable"):
        await registry.execute(
            "health_check",
            request,
            ToolExecutionContext(
                request=request,
                settings=Settings(environment="test"),
                audit_writer=FailingAuditWriter(),
            ),
        )


async def test_optional_observability_degradation_does_not_block_readiness() -> None:
    payload = await build_readiness_payload(
        Settings(environment="test"),
        {
            "postgresql": StaticDependencyChecker(
                name="postgresql",
                required=True,
                status="ok",
                detail="query succeeded",
            ),
            "alerts": StaticDependencyChecker(
                name="alerts",
                required=False,
                status="unavailable",
                detail="alert backend unavailable",
            ),
        },
    )

    assert payload.status == "ready"
    assert payload.dependencies["alerts"].status == "unavailable"
