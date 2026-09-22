from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from proxmox_mcp.persistence.database import build_session_factory
from proxmox_mcp.persistence.models import Base
from proxmox_mcp.schemas.envelope import Actor
from proxmox_mcp.ssh.client import SshCommandResult, SshTarget
from proxmox_mcp.ssh.recording import DatabaseSshRecordingStore
from proxmox_mcp.ssh.sessions import (
    DatabaseSshSessionStore,
    SshSessionLimitError,
    SshSessionNotFoundError,
)


async def test_database_ssh_session_store_shares_sessions_across_instances(
    tmp_path: Path,
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'ssh-sessions.db').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    store_a = DatabaseSshSessionStore(build_session_factory(engine), max_sessions_per_actor_node=1)
    store_b = DatabaseSshSessionStore(build_session_factory(engine), max_sessions_per_actor_node=1)
    actor = Actor(user_id="user-1", agent_id="agent-1", tenant_id="tenant-1")
    target = SshTarget(cluster="lab", node="pve-a")

    opened = await store_a.open_session(actor=actor, target=target, interactive=True)
    resolved = await store_b.get_active_session(opened.session_id)
    with pytest.raises(SshSessionLimitError):
        await store_b.open_session(actor=actor, target=target, interactive=True)
    closed = await store_b.close_session(opened.session_id)
    with pytest.raises(SshSessionNotFoundError):
        await store_a.get_active_session(opened.session_id)
    await engine.dispose()

    assert resolved.session_id == opened.session_id
    assert closed.closed_at is not None


async def test_database_ssh_recording_store_persists_redacted_recordings(
    tmp_path: Path,
) -> None:
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'ssh-recordings.db').as_posix()}"
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    store_a = DatabaseSshRecordingStore(build_session_factory(engine))
    store_b = DatabaseSshRecordingStore(build_session_factory(engine))

    recording = await store_a.record_command(
        request_id="req-1",
        session_id="ssh_session_1",
        command_hash="abc123",
        result=SshCommandResult(
            exit_status=0,
            stdout="token=secret-value",
            stderr="password: hunter2",
            duration_ms=42,
        ),
        redaction_profile="default",
    )
    resolved = await store_b.get_recording(recording.recording_ref)
    await engine.dispose()

    assert resolved.stdout == "token=[REDACTED]"
    assert resolved.stderr == "password=[REDACTED]"
    assert resolved.exit_status == 0
