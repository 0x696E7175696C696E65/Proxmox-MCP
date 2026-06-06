from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.audit.writer import InMemoryAuditWriter


def test_audit_event_contains_required_identity_fields() -> None:
    event = AuditEvent(
        event_type="tool.execution.started",
        correlation_id="corr_123",
        actor_user_id="user_123",
        actor_agent_id="agent_123",
        tool_name="health_check",
        operation="internal.health.read",
        target=AuditTarget(resource_type="internal", resource_id="health"),
        result_status="started",
    )

    assert event.event_id.startswith("audit_")
    assert event.actor_user_id == "user_123"
    assert event.target.resource_type == "internal"


def test_audit_event_default_timestamp_is_aware_utc() -> None:
    event = AuditEvent(
        event_type="tool.execution.started",
        correlation_id="corr_123",
        actor_user_id="user_123",
        actor_agent_id="agent_123",
        tool_name="health_check",
        operation="internal.health.read",
        target=AuditTarget(resource_type="internal", resource_id="health"),
        result_status="started",
    )

    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timedelta(0)


def test_audit_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            timestamp=datetime(2026, 1, 1),
            event_type="tool.execution.started",
            correlation_id="corr_123",
            actor_user_id="user_123",
            actor_agent_id="agent_123",
            tool_name="health_check",
            operation="internal.health.read",
            target=AuditTarget(resource_type="internal", resource_id="health"),
            result_status="started",
        )


def test_audit_event_normalizes_aware_timestamp_to_utc() -> None:
    event = AuditEvent(
        timestamp=datetime(2026, 1, 1, 12, tzinfo=timezone(timedelta(hours=2))),
        event_type="tool.execution.started",
        correlation_id="corr_123",
        actor_user_id="user_123",
        actor_agent_id="agent_123",
        tool_name="health_check",
        operation="internal.health.read",
        target=AuditTarget(resource_type="internal", resource_id="health"),
        result_status="started",
    )

    assert event.timestamp == datetime(2026, 1, 1, 10, tzinfo=UTC)
    assert event.timestamp.utcoffset() == timedelta(0)


async def test_in_memory_audit_writer_records_events() -> None:
    writer = InMemoryAuditWriter()
    event = AuditEvent(
        event_type="tool.execution.finished",
        correlation_id="corr_123",
        actor_user_id="user_123",
        actor_agent_id="agent_123",
        tool_name="health_check",
        operation="internal.health.read",
        target=AuditTarget(resource_type="internal", resource_id="health"),
        result_status="success",
    )

    await writer.write(event)

    assert writer.events == [event]
