from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.audit.repository import DatabaseAuditWriter
from proxmox_mcp.persistence.models import AuditEventRecord, Base


def _audit_event() -> AuditEvent:
    return AuditEvent(
        event_id="audit_test_123",
        timestamp=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        event_type="tool.execution.finished",
        correlation_id="corr_123",
        tenant_id="tenant_123",
        actor_user_id="user_123",
        actor_agent_id="agent_123",
        tool_name="health_check",
        operation="internal.health.read",
        target=AuditTarget(
            cluster_id="cluster_123",
            node_id="node_123",
            resource_type="internal",
            resource_id="health",
            metadata={"scope": "readiness"},
        ),
        result_status="success",
        exit_code=0,
        duration_ms=17,
        metadata={
            "request_id": "req_123",
            "observed_at": datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
        },
    )


async def test_database_audit_writer_persists_event() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    writer = DatabaseAuditWriter(session_factory)
    event = _audit_event()

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    try:
        await writer.write(event)

        async with session_factory() as session:
            record = await session.scalar(
                select(AuditEventRecord).where(AuditEventRecord.event_id == event.event_id)
            )

        assert record is not None
        assert record.event_id == event.event_id
        assert record.event_type == event.event_type
        assert record.tenant_id == event.tenant_id
        assert record.cluster_id == event.target.cluster_id
        assert record.node_id == event.target.node_id
        assert record.result_status == "success"
        assert record.exit_code == 0
        assert record.duration_ms == 17
        assert record.target_json == event.target.model_dump(mode="json")
        assert record.metadata_json == event.model_dump(mode="json")["metadata"]
        assert record.metadata_json["observed_at"] == "2026-01-01T12:01:00Z"
        assert record.event_json == event.model_dump(mode="json")
        assert record.event_json["timestamp"] == "2026-01-01T12:00:00Z"
    finally:
        await engine.dispose()


async def test_database_audit_writer_propagates_database_errors() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine,
        expire_on_commit=False,
    )
    writer = DatabaseAuditWriter(session_factory)

    try:
        with pytest.raises(SQLAlchemyError):
            await writer.write(_audit_event())
    finally:
        await engine.dispose()
