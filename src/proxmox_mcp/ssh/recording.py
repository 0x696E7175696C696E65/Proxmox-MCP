from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

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


def _redact(value: str, redaction_profile: str) -> str:
    if redaction_profile == "none":
        return value

    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}=[REDACTED]", redacted)
    return redacted
