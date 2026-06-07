from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.persistence.models import SshRecordingRecord
from proxmox_mcp.ssh.client import SshCommandResult

_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|token|secret|key)=\S+"),
    re.compile(r"(?i)(password|token|secret|key):\s*\S+"),
)


class SshRecording(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recording_ref: str
    request_id: str
    session_id: str | None = None
    command_hash: str | None = None
    stdout: str = ""
    stderr: str = ""
    exit_status: int | None = None
    redacted: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SshRecordingStore(Protocol):
    async def record_command(
        self,
        *,
        request_id: str,
        session_id: str | None,
        command_hash: str,
        result: SshCommandResult,
        redaction_profile: str,
    ) -> SshRecording: ...

    async def reserve_session_recording(
        self,
        *,
        request_id: str,
        session_id: str,
    ) -> SshRecording: ...

    async def get_recording(self, recording_ref: str) -> SshRecording: ...


def _empty_recordings() -> list[SshRecording]:
    return []


@dataclass(slots=True)
class InMemorySshRecordingStore:
    recordings: list[SshRecording] = field(default_factory=_empty_recordings)

    async def record_command(
        self,
        *,
        request_id: str,
        session_id: str | None,
        command_hash: str,
        result: SshCommandResult,
        redaction_profile: str,
    ) -> SshRecording:
        recording = SshRecording(
            recording_ref=f"ssh_recording_{uuid4().hex}",
            request_id=request_id,
            session_id=session_id,
            command_hash=command_hash,
            stdout=_redact(result.stdout, redaction_profile),
            stderr=_redact(result.stderr, redaction_profile),
            exit_status=result.exit_status,
            redacted=redaction_profile != "none",
        )
        self.recordings.append(recording)
        return recording

    async def reserve_session_recording(
        self,
        *,
        request_id: str,
        session_id: str,
    ) -> SshRecording:
        recording = SshRecording(
            recording_ref=f"ssh_recording_{uuid4().hex}",
            request_id=request_id,
            session_id=session_id,
            redacted=True,
        )
        self.recordings.append(recording)
        return recording

    async def get_recording(self, recording_ref: str) -> SshRecording:
        for recording in self.recordings:
            if recording.recording_ref == recording_ref:
                return recording
        raise KeyError(recording_ref)


class DatabaseSshRecordingStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record_command(
        self,
        *,
        request_id: str,
        session_id: str | None,
        command_hash: str,
        result: SshCommandResult,
        redaction_profile: str,
    ) -> SshRecording:
        recording = SshRecording(
            recording_ref=f"ssh_recording_{uuid4().hex}",
            request_id=request_id,
            session_id=session_id,
            command_hash=command_hash,
            stdout=_redact(result.stdout, redaction_profile),
            stderr=_redact(result.stderr, redaction_profile),
            exit_status=result.exit_status,
            redacted=redaction_profile != "none",
        )
        await self._insert_recording(recording)
        return recording

    async def reserve_session_recording(
        self,
        *,
        request_id: str,
        session_id: str,
    ) -> SshRecording:
        recording = SshRecording(
            recording_ref=f"ssh_recording_{uuid4().hex}",
            request_id=request_id,
            session_id=session_id,
            redacted=True,
        )
        await self._insert_recording(recording)
        return recording

    async def get_recording(self, recording_ref: str) -> SshRecording:
        async with self._session_factory() as session:
            record = await session.scalar(
                select(SshRecordingRecord).where(SshRecordingRecord.recording_ref == recording_ref)
            )
            if record is None:
                raise KeyError(recording_ref)
            return _recording_from_model(record)

    async def _insert_recording(self, recording: SshRecording) -> None:
        async with self._session_factory() as session:
            session.add(_recording_to_model(recording))
            await session.commit()


def _recording_to_model(recording: SshRecording) -> SshRecordingRecord:
    return SshRecordingRecord(
        recording_ref=recording.recording_ref,
        request_id=recording.request_id,
        session_id=recording.session_id,
        command_hash=recording.command_hash,
        stdout=recording.stdout,
        stderr=recording.stderr,
        exit_status=recording.exit_status,
        redacted=recording.redacted,
        created_at=recording.created_at,
    )


def _recording_from_model(record: SshRecordingRecord) -> SshRecording:
    return SshRecording(
        recording_ref=record.recording_ref,
        request_id=record.request_id,
        session_id=record.session_id,
        command_hash=record.command_hash,
        stdout=record.stdout,
        stderr=record.stderr,
        exit_status=record.exit_status,
        redacted=record.redacted,
        created_at=_as_aware(record.created_at),
    )


def _redact(value: str, redaction_profile: str) -> str:
    if redaction_profile == "none":
        return value

    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}=[REDACTED]", redacted)
    return redacted


def _as_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
