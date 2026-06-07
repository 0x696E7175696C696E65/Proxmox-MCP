from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from proxmox_mcp.audit.writer import AuditWriter
from proxmox_mcp.auth import AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.schemas.envelope import Actor, Target, ToolRequest

if TYPE_CHECKING:
    from proxmox_mcp.audit.repository import AuditEventRepository
    from proxmox_mcp.observability import AlertBackend, InMemoryMetricsRegistry, TrendBackend
    from proxmox_mcp.proxmox.client import ProxmoxApiClient
    from proxmox_mcp.reliability import IdempotencyStore, ProxmoxTaskStore
    from proxmox_mcp.ssh.client import SshClient
    from proxmox_mcp.ssh.policy import SshCommandPolicy
    from proxmox_mcp.ssh.recording import SshRecordingStore
    from proxmox_mcp.ssh.sessions import SshSessionManager, SshSessionStore


def _empty_audit_metadata() -> dict[str, object]:
    return {}


@dataclass(frozen=True, slots=True)
class ToolExecutionContext:
    request: ToolRequest
    settings: Settings
    audit_writer: AuditWriter
    authenticated_session: AuthenticatedSession | None = None
    proxmox_client: ProxmoxApiClient | None = None
    ssh_client: SshClient | None = None
    ssh_command_policy: SshCommandPolicy | None = None
    ssh_session_manager: SshSessionManager | None = None
    ssh_session_store: SshSessionStore | None = None
    ssh_recording_store: SshRecordingStore | None = None
    audit_repository: AuditEventRepository | None = None
    metrics_registry: InMemoryMetricsRegistry | None = None
    alert_backend: AlertBackend | None = None
    trend_backend: TrendBackend | None = None
    idempotency_store: IdempotencyStore | None = None
    proxmox_task_store: ProxmoxTaskStore | None = None
    audit_metadata: dict[str, object] = field(default_factory=_empty_audit_metadata)

    @property
    def request_id(self) -> str:
        return self.request.request_id

    @property
    def correlation_id(self) -> str:
        return self.request.correlation_id

    @property
    def actor(self) -> Actor:
        return self.request.actor

    @property
    def target(self) -> Target:
        return self.request.target
