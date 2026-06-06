from __future__ import annotations

from typing import Literal

from fastmcp import FastMCP

from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.audit.writer import AuditWriter, InMemoryAuditWriter
from proxmox_mcp.config import Settings


def build_health_payload(settings: Settings) -> dict[str, str | int]:
    return {
        "status": "ok",
        "service": "enterprise-proxmox-mcp",
        "environment": settings.environment,
        "port": settings.server_port,
    }


def _health_audit_event(
    event_type: str,
    result_status: Literal["started", "success"],
) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        correlation_id="health_check",
        actor_user_id="system",
        actor_agent_id="system",
        tool_name="health_check",
        operation="internal.health.read",
        target=AuditTarget(resource_type="internal", resource_id="health"),
        result_status=result_status,
    )


async def health_check(
    settings: Settings,
    audit_writer: AuditWriter,
) -> dict[str, str | int]:
    await audit_writer.write(
        _health_audit_event(event_type="tool.execution.started", result_status="started")
    )

    payload = build_health_payload(settings)

    await audit_writer.write(
        _health_audit_event(event_type="tool.execution.finished", result_status="success")
    )

    return payload


def build_server(
    settings: Settings | None = None,
    audit_writer: AuditWriter | None = None,
) -> FastMCP:
    settings = Settings() if settings is None else settings
    audit_writer = InMemoryAuditWriter() if audit_writer is None else audit_writer

    app = FastMCP("Enterprise Proxmox MCP")

    @app.tool(name="health_check")
    async def health_check_tool() -> dict[str, str | int]:  # pyright: ignore[reportUnusedFunction]
        """Registered by FastMCP through the decorator above."""
        return await health_check(settings, audit_writer)

    return app


def run() -> None:
    build_server().run()
