from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.server.app import build_health_payload, build_server, health_check


def test_health_payload_reports_runtime_status() -> None:
    payload = build_health_payload(Settings(environment="test"))

    assert payload["status"] == "ok"
    assert payload["service"] == "enterprise-proxmox-mcp"
    assert payload["environment"] == "test"
    assert payload["port"] == 8080


def test_build_server_returns_named_app() -> None:
    app = build_server(Settings(environment="test"), InMemoryAuditWriter())

    assert app.name == "Enterprise Proxmox MCP"


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
