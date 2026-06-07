from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.persistence.models import SshSessionRecordModel
from proxmox_mcp.schemas.envelope import Actor
from proxmox_mcp.ssh.client import SshTarget


class SshSessionLimitError(RuntimeError):
    pass


class SshSessionNotFoundError(RuntimeError):
    pass


class SshSessionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    actor_user_id: str
    actor_agent_id: str
    tenant_id: str | None = None
    target: SshTarget
    interactive: bool
    opened_at: datetime
    expires_at: datetime
    closed_at: datetime | None = None
    recording_ref: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.closed_at is None and self.expires_at > datetime.now(UTC)


class SshSessionStore(Protocol):
    async def open_session(
        self,
        *,
        actor: Actor,
        target: SshTarget,
        interactive: bool,
        recording_ref: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SshSessionRecord: ...

    async def get_active_session(self, session_id: str) -> SshSessionRecord: ...

    async def close_session(self, session_id: str) -> SshSessionRecord: ...

    async def attach_recording(self, session_id: str, recording_ref: str) -> SshSessionRecord: ...


def _empty_sessions() -> dict[str, SshSessionRecord]:
    return {}


@dataclass(slots=True)
class SshSessionManager:
    durable: bool = False
    max_sessions_per_actor_node: int = 2
    session_ttl_seconds: int = 900
    _sessions: dict[str, SshSessionRecord] = field(default_factory=_empty_sessions)

    def open_session(
        self,
        *,
        actor: Actor,
        target: SshTarget,
        interactive: bool,
        recording_ref: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SshSessionRecord:
        self._expire_old_sessions()
        if self._active_count(actor=actor, target=target) >= self.max_sessions_per_actor_node:
            raise SshSessionLimitError("SSH session limit exceeded for actor and node")

        now = datetime.now(UTC)
        record = SshSessionRecord(
            session_id=f"ssh_session_{uuid4().hex}",
            actor_user_id=actor.user_id,
            actor_agent_id=actor.agent_id,
            tenant_id=actor.tenant_id,
            target=target,
            interactive=interactive,
            opened_at=now,
            expires_at=now + timedelta(seconds=self.session_ttl_seconds),
            recording_ref=recording_ref,
            metadata={} if metadata is None else metadata,
        )
        self._sessions[record.session_id] = record
        return record

    def get_active_session(self, session_id: str) -> SshSessionRecord:
        record = self._sessions.get(session_id)
        if record is None or not record.active:
            raise SshSessionNotFoundError("SSH session is not active")
        return record

    def close_session(self, session_id: str) -> SshSessionRecord:
        record = self.get_active_session(session_id)
        updated = record.model_copy(update={"closed_at": datetime.now(UTC)})
        self._sessions[session_id] = updated
        return updated

    def attach_recording(self, session_id: str, recording_ref: str) -> SshSessionRecord:
        record = self.get_active_session(session_id)
        updated = record.model_copy(update={"recording_ref": recording_ref})
        self._sessions[session_id] = updated
        return updated

    def _active_count(self, *, actor: Actor, target: SshTarget) -> int:
        return sum(
            1
            for record in self._sessions.values()
            if record.active
            and record.actor_user_id == actor.user_id
            and record.actor_agent_id == actor.agent_id
            and record.tenant_id == actor.tenant_id
            and record.target.node == target.node
        )

    def _expire_old_sessions(self) -> None:
        now = datetime.now(UTC)
        for session_id, record in list(self._sessions.items()):
            if record.closed_at is None and record.expires_at <= now:
                self._sessions[session_id] = record.model_copy(update={"closed_at": now})


class DatabaseSshSessionStore:
    durable: bool = True

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        max_sessions_per_actor_node: int = 2,
        session_ttl_seconds: int = 900,
    ) -> None:
        self._session_factory = session_factory
        self._max_sessions_per_actor_node = max_sessions_per_actor_node
        self._session_ttl_seconds = session_ttl_seconds

    async def open_session(
        self,
        *,
        actor: Actor,
        target: SshTarget,
        interactive: bool,
        recording_ref: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SshSessionRecord:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            await self._expire_old_sessions(session, now)
            active_count = await session.scalar(
                select(func.count())
                .select_from(SshSessionRecordModel)
                .where(SshSessionRecordModel.closed_at.is_(None))
                .where(SshSessionRecordModel.expires_at > now)
                .where(SshSessionRecordModel.actor_user_id == actor.user_id)
                .where(SshSessionRecordModel.actor_agent_id == actor.agent_id)
                .where(SshSessionRecordModel.tenant_id == actor.tenant_id)
                .where(SshSessionRecordModel.node_id == target.node)
            )
            if int(active_count or 0) >= self._max_sessions_per_actor_node:
                raise SshSessionLimitError("SSH session limit exceeded for actor and node")

            record = SshSessionRecord(
                session_id=f"ssh_session_{uuid4().hex}",
                actor_user_id=actor.user_id,
                actor_agent_id=actor.agent_id,
                tenant_id=actor.tenant_id,
                target=target,
                interactive=interactive,
                opened_at=now,
                expires_at=now + timedelta(seconds=self._session_ttl_seconds),
                recording_ref=recording_ref,
                metadata={} if metadata is None else metadata,
            )
            session.add(_record_to_model(record))
            await session.commit()
            return record

    async def get_active_session(self, session_id: str) -> SshSessionRecord:
        async with self._session_factory() as session:
            model = await session.scalar(
                select(SshSessionRecordModel).where(SshSessionRecordModel.session_id == session_id)
            )
            if model is None:
                raise SshSessionNotFoundError("SSH session is not active")
            record = _model_to_record(model)
            if not record.active:
                raise SshSessionNotFoundError("SSH session is not active")
            return record

    async def close_session(self, session_id: str) -> SshSessionRecord:
        record = await self.get_active_session(session_id)
        closed_at = datetime.now(UTC)
        updated = record.model_copy(update={"closed_at": closed_at})
        async with self._session_factory() as session:
            await session.execute(
                update(SshSessionRecordModel)
                .where(SshSessionRecordModel.session_id == session_id)
                .where(SshSessionRecordModel.closed_at.is_(None))
                .values(closed_at=closed_at)
            )
            await session.commit()
        return updated

    async def attach_recording(self, session_id: str, recording_ref: str) -> SshSessionRecord:
        record = await self.get_active_session(session_id)
        updated = record.model_copy(update={"recording_ref": recording_ref})
        async with self._session_factory() as session:
            await session.execute(
                update(SshSessionRecordModel)
                .where(SshSessionRecordModel.session_id == session_id)
                .values(recording_ref=recording_ref)
            )
            await session.commit()
        return updated

    async def _expire_old_sessions(self, session: AsyncSession, now: datetime) -> None:
        await session.execute(
            update(SshSessionRecordModel)
            .where(SshSessionRecordModel.closed_at.is_(None))
            .where(SshSessionRecordModel.expires_at <= now)
            .values(closed_at=now)
        )


def _record_to_model(record: SshSessionRecord) -> SshSessionRecordModel:
    return SshSessionRecordModel(
        session_id=record.session_id,
        actor_user_id=record.actor_user_id,
        actor_agent_id=record.actor_agent_id,
        tenant_id=record.tenant_id,
        cluster_id=record.target.cluster,
        node_id=record.target.node,
        interactive=record.interactive,
        opened_at=record.opened_at,
        expires_at=record.expires_at,
        closed_at=record.closed_at,
        recording_ref=record.recording_ref,
        metadata_json=record.metadata,
    )


def _model_to_record(model: SshSessionRecordModel) -> SshSessionRecord:
    return SshSessionRecord(
        session_id=model.session_id,
        actor_user_id=model.actor_user_id,
        actor_agent_id=model.actor_agent_id,
        tenant_id=model.tenant_id,
        target=SshTarget(cluster=model.cluster_id, node=model.node_id),
        interactive=model.interactive,
        opened_at=_as_aware(model.opened_at),
        expires_at=_as_aware(model.expires_at),
        closed_at=None if model.closed_at is None else _as_aware(model.closed_at),
        recording_ref=model.recording_ref,
        metadata=model.metadata_json,
    )


def _as_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
