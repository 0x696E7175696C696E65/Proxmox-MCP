from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

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


def _empty_sessions() -> dict[str, SshSessionRecord]:
    return {}


@dataclass(slots=True)
class SshSessionManager:
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
