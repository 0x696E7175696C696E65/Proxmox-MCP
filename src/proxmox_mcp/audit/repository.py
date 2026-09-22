from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import ColumnElement, and_, select
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
        tool_name: str | None = None,
        result_status: str | None = None,
        actor_user_id: str | None = None,
        before: datetime | None = None,
        after: datetime | None = None,
        cursor: str | None = None,
    ) -> list[dict[str, object]]: ...

    async def get_event(self, event_id: str) -> dict[str, object] | None: ...


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


class PublishingAuditWriter(AuditWriter):
    """Wraps an audit writer and notifies the admin event hub."""

    def __init__(self, inner: AuditWriter, publish: object) -> None:
        self._inner = inner
        self._publish = publish

    async def write(self, event: AuditEvent) -> None:
        await self._inner.write(event)
        publish = getattr(self._publish, "publish", None)
        if publish is not None:
            await publish("audit.created", event.model_dump(mode="json"))


class DatabaseAuditEventRepository(AuditEventRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_events(
        self,
        *,
        limit: int = 100,
        tenant_id: str | None = None,
        tool_name: str | None = None,
        result_status: str | None = None,
        actor_user_id: str | None = None,
        before: datetime | None = None,
        after: datetime | None = None,
        cursor: str | None = None,
    ) -> list[dict[str, object]]:
        filters: list[ColumnElement[Any]] = []
        if tenant_id is not None:
            filters.append(AuditEventRecord.tenant_id == tenant_id)
        if tool_name is not None:
            filters.append(AuditEventRecord.tool_name == tool_name)
        if result_status is not None:
            filters.append(AuditEventRecord.result_status == result_status)
        if actor_user_id is not None:
            filters.append(AuditEventRecord.actor_user_id == actor_user_id)
        if before is not None:
            filters.append(AuditEventRecord.timestamp < before)
        if after is not None:
            filters.append(AuditEventRecord.timestamp > after)
        if cursor is not None:
            filters.append(AuditEventRecord.event_id < cursor)

        statement = select(AuditEventRecord).order_by(
            AuditEventRecord.timestamp.desc(),
            AuditEventRecord.event_id.desc(),
        )
        if filters:
            statement = statement.where(and_(*filters))
        statement = statement.limit(min(max(limit, 1), 500))

        async with self._session_factory() as session:
            records = (await session.scalars(statement)).all()

        return [record.event_json for record in records]

    async def get_event(self, event_id: str) -> dict[str, object] | None:
        async with self._session_factory() as session:
            record = await session.get(AuditEventRecord, event_id)
        if record is None:
            return None
        return record.event_json
