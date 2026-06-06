from __future__ import annotations

from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.audit.events import AuditEvent
from proxmox_mcp.audit.writer import AuditWriter
from proxmox_mcp.persistence.models import AuditEventRecord


class AuditEventRepository(Protocol):
    async def list_events(
        self,
        *,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, object]]: ...


class DatabaseAuditWriter(AuditWriter):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def write(self, event: AuditEvent) -> None:
        serialized = event.model_dump(mode="json")
        record = AuditEventRecord(
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            correlation_id=event.correlation_id,
            tenant_id=event.tenant_id,
            actor_user_id=event.actor_user_id,
            actor_agent_id=event.actor_agent_id,
            tool_name=event.tool_name,
            operation=event.operation,
            resource_type=event.target.resource_type,
            resource_id=event.target.resource_id,
            cluster_id=event.target.cluster_id,
            node_id=event.target.node_id,
            result_status=event.result_status,
            exit_code=event.exit_code,
            duration_ms=event.duration_ms,
            error_code=event.error_code,
            target_json=serialized["target"],
            metadata_json=serialized["metadata"],
            event_json=serialized,
        )

        async with self._session_factory() as session:
            session.add(record)
            await session.commit()


class DatabaseAuditEventRepository(AuditEventRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_events(
        self,
        *,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, object]]:
        statement = (
            select(AuditEventRecord).order_by(AuditEventRecord.timestamp.desc()).limit(limit)
        )
        if tenant_id is not None:
            statement = statement.where(AuditEventRecord.tenant_id == tenant_id)

        async with self._session_factory() as session:
            records = (await session.scalars(statement)).all()

        return [record.event_json for record in records]
