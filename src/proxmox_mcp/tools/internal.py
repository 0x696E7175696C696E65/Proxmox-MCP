from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from proxmox_mcp.config import Settings
from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolRegistry


class EmptyParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(min_length=1)
    service: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)


def build_health_payload(settings: Settings) -> dict[str, str | int]:
    return {
        "status": "ok",
        "service": "enterprise-proxmox-mcp",
        "environment": settings.environment,
        "port": settings.server_port,
    }


async def health_check_handler(
    request: ToolRequest,
    context: ToolExecutionContext,
) -> dict[str, str | int]:
    return build_health_payload(context.settings)


HEALTH_CHECK_DEFINITION = ToolDefinition(
    name="health_check",
    description=(
        "Internal liveness probe. Returns the server status, service name, "
        "environment, and configured port. Takes no parameters and never touches "
        "Proxmox; safe to call at any time."
    ),
    category="internal",
    permission="internal.health.read",
    risk="low",
    dry_run=True,
    approval_default=False,
    connector="internal",
    handler=health_check_handler,
    parameters_model=EmptyParameters,
    result_model=HealthPayload,
)


def register_internal_tools(registry: ToolRegistry) -> None:
    registry.register(HEALTH_CHECK_DEFINITION)
