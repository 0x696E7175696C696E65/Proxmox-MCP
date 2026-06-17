from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import cast

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from proxmox_mcp.approvals import DatabaseApprovalStore
from proxmox_mcp.audit.repository import DatabaseAuditEventRepository, DatabaseAuditWriter
from proxmox_mcp.audit.writer import AuditWriter
from proxmox_mcp.auth import AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.observability import (
    DatabaseSiemDeliveryQueue,
    SiemQueueingAuditWriter,
)
from proxmox_mcp.persistence.database import build_async_engine, build_session_factory
from proxmox_mcp.proxmox.circuit_client import CircuitBreakerProxmoxClient
from proxmox_mcp.proxmox.client import ProxmoxApiClient
from proxmox_mcp.proxmox.cluster_factory import (
    cluster_config_from_settings,
    normalize_proxmox_api_endpoint,
)
from proxmox_mcp.proxmox.config import ClusterCredentialResolver, ResolvedProxmoxCluster
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.reliability import (
    CircuitBreaker,
    DatabaseIdempotencyStore,
    DatabaseProxmoxTaskStore,
)
from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.secrets.factory import build_secret_manager
from proxmox_mcp.server.auth_resolver import build_auth_resolver
from proxmox_mcp.server.health import (
    AlembicMigrationDependencyChecker,
    DependencyChecker,
    ProductionStateDependencyChecker,
    SiemDeliveryDependencyChecker,
    default_dependency_checkers,
)
from proxmox_mcp.ssh.client import SshClient
from proxmox_mcp.ssh.recording import DatabaseSshRecordingStore
from proxmox_mcp.ssh.sessions import DatabaseSshSessionStore


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    settings: Settings
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    audit_writer: AuditWriter
    audit_repository: DatabaseAuditEventRepository
    approval_store: DatabaseApprovalStore
    idempotency_store: DatabaseIdempotencyStore
    proxmox_task_store: DatabaseProxmoxTaskStore
    ssh_session_store: DatabaseSshSessionStore
    ssh_recording_store: DatabaseSshRecordingStore
    proxmox_client: ProxmoxApiClient | None
    ssh_client: SshClient | None
    authenticated_session_resolver: Callable[[ToolRequest], AuthenticatedSession | None] | None
    dependency_checkers: Mapping[str, DependencyChecker]
    circuit_breaker: CircuitBreaker


def build_runtime(settings: Settings) -> RuntimeBundle:
    return asyncio.run(build_runtime_async(settings))


async def build_runtime_async(settings: Settings) -> RuntimeBundle:
    if not settings.durable_state_enabled:
        raise ValueError("Durable runtime requires PROXMOX_MCP_DURABLE_STATE_ENABLED=true")

    engine = build_async_engine(settings)
    session_factory = build_session_factory(engine)
    secret_manager = build_secret_manager(settings)
    audit_repository = DatabaseAuditEventRepository(session_factory)
    base_audit_writer = DatabaseAuditWriter(session_factory)
    audit_writer: AuditWriter = base_audit_writer
    siem_configured = False

    if settings.observability.siem_url is not None:
        siem_queue = DatabaseSiemDeliveryQueue(session_factory)
        audit_writer = SiemQueueingAuditWriter(
            base_audit_writer,
            delivery_queue=siem_queue,
            destination=settings.observability.siem_url,
        )
        siem_configured = True

    approval_store = DatabaseApprovalStore(session_factory)
    idempotency_store = DatabaseIdempotencyStore(session_factory)
    proxmox_task_store = DatabaseProxmoxTaskStore(session_factory)
    ssh_session_store = DatabaseSshSessionStore(session_factory)
    ssh_recording_store = DatabaseSshRecordingStore(session_factory)
    circuit_breaker = CircuitBreaker()

    proxmox_client = await _build_proxmox_client(settings, secret_manager, circuit_breaker)
    auth_resolver = build_auth_resolver(settings)
    # ssh optional for homelab v1
    dependency_checkers = dict(default_dependency_checkers())
    dependency_checkers["production_state"] = ProductionStateDependencyChecker(
        durable_components_configured=True,
        approval_store_configured=True,
    )
    dependency_checkers["migrations"] = AlembicMigrationDependencyChecker()
    dependency_checkers["siem_delivery"] = SiemDeliveryDependencyChecker(configured=siem_configured)

    return RuntimeBundle(
        settings=settings,
        engine=engine,
        session_factory=session_factory,
        audit_writer=audit_writer,
        audit_repository=audit_repository,
        approval_store=approval_store,
        idempotency_store=idempotency_store,
        proxmox_task_store=proxmox_task_store,
        ssh_session_store=ssh_session_store,
        ssh_recording_store=ssh_recording_store,
        proxmox_client=proxmox_client,
        ssh_client=None,
        authenticated_session_resolver=auth_resolver,
        dependency_checkers=dependency_checkers,
        circuit_breaker=circuit_breaker,
    )


async def _build_proxmox_client(
    settings: Settings,
    secret_manager: object,
    circuit_breaker: CircuitBreaker,
) -> ProxmoxApiClient | None:
    cluster_config = cluster_config_from_settings(settings)
    if cluster_config is None:
        return None

    from proxmox_mcp.secrets import SecretManager

    if not isinstance(secret_manager, SecretManager):
        raise TypeError("secret_manager must be a SecretManager")

    resolver = ClusterCredentialResolver(secret_manager)
    resolved = await resolver.resolve(cluster_config)
    http_client = _proxmox_http_client_from_cluster(resolved)
    return cast(
        ProxmoxApiClient,
        CircuitBreakerProxmoxClient(http_client, circuit_breaker=circuit_breaker),
    )


def _proxmox_http_client_from_cluster(resolved: ResolvedProxmoxCluster) -> ProxmoxHttpApiClient:
    endpoint = normalize_proxmox_api_endpoint(resolved.api_endpoint)
    credential = resolved.credential
    if credential.auth_type == "api_token":
        if credential.token_id is None or credential.token_secret is None:
            raise ValueError("Resolved API token credentials are incomplete")
        return ProxmoxHttpApiClient(
            api_endpoint=endpoint,
            token_id=credential.token_id,
            token_secret=credential.token_secret,
            tls_verify=resolved.tls_verify,
        )

    if credential.username is None or credential.password is None:
        raise ValueError("Resolved username/password credentials are incomplete")
    return ProxmoxHttpApiClient(
        api_endpoint=endpoint,
        username=credential.username,
        password=credential.password,
        tls_verify=resolved.tls_verify,
    )
