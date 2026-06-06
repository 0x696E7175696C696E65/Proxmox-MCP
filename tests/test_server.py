from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    DANGEROUS_TOOL_SPECS,
    DOMAIN_COMPLETION_TOOL_SPECS,
    READ_ONLY_TOOL_SPECS,
    SAFE_MUTATION_TOOL_SPECS,
)
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.server.app import build_health_payload, build_server, health_check
from proxmox_mcp.ssh.tools import SSH_TOOL_SPECS
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.internal import HEALTH_CHECK_DEFINITION
from proxmox_mcp.tools.registry import ToolRegistry


def test_health_payload_reports_runtime_status() -> None:
    payload = build_health_payload(Settings(environment="test"))

    assert payload["status"] == "ok"
    assert payload["service"] == "enterprise-proxmox-mcp"
    assert payload["environment"] == "test"
    assert payload["port"] == 8080


def test_build_server_returns_named_app() -> None:
    app = build_server(Settings(environment="test"), InMemoryAuditWriter())

    assert app.name == "Enterprise Proxmox MCP"


async def test_build_server_registers_health_and_read_only_tools() -> None:
    app = build_server(Settings(environment="test"), InMemoryAuditWriter())

    tools = await app.list_tools()

    tool_names = [tool.name for tool in tools]
    assert tool_names[0] == "health_check"
    assert set(tool_names[1:]) == {spec.name for spec in READ_ONLY_TOOL_SPECS} | {
        spec.name for spec in SAFE_MUTATION_TOOL_SPECS
    } | {spec.name for spec in DANGEROUS_TOOL_SPECS} | {
        spec.name for spec in DOMAIN_COMPLETION_TOOL_SPECS
    } | {spec.name for spec in SSH_TOOL_SPECS}


async def test_health_check_writes_audit_event() -> None:
    writer = InMemoryAuditWriter()

    payload = await health_check(Settings(environment="test"), writer)

    assert payload["status"] == "ok"
    assert len(writer.events) == 2

    started_event = writer.events[0]
    success_event = writer.events[1]

    assert started_event.result_status == "started"
    assert success_event.result_status == "success"

    for event in writer.events:
        assert event.tool_name == "health_check"
        assert event.operation == "internal.health.read"
        assert event.target.resource_type == "internal"
        assert event.target.resource_id == "health"
        assert event.actor_user_id == "system"
        assert event.actor_agent_id == "system"
        assert event.correlation_id == "health_check"


async def test_legacy_health_check_uses_registry_audit_metadata() -> None:
    settings = Settings(environment="test")
    legacy_writer = InMemoryAuditWriter()
    registry_writer = InMemoryAuditWriter()
    registry = ToolRegistry()
    registry.register(HEALTH_CHECK_DEFINITION)
    request = ToolRequest(
        request_id="health_check",
        correlation_id="health_check",
        actor=Actor(user_id="system", agent_id="system"),
        target=Target(resource_type="internal", resource_id="health"),
        options=RequestOptions(dry_run=True),
    )

    legacy_payload = await health_check(settings, legacy_writer)
    registry_response = await registry.execute(
        "health_check",
        request,
        ToolExecutionContext(
            request=request,
            settings=settings,
            audit_writer=registry_writer,
        ),
    )

    assert isinstance(registry_response, ToolResponse)
    assert legacy_payload == registry_response.result
    assert [
        event.model_dump(exclude={"event_id", "timestamp"}) for event in legacy_writer.events
    ] == [event.model_dump(exclude={"event_id", "timestamp"}) for event in registry_writer.events]
