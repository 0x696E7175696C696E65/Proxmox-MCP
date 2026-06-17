from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import cast

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

from proxmox_mcp.audit.repository import AuditEventRepository
from proxmox_mcp.audit.writer import AuditWriter, InMemoryAuditWriter
from proxmox_mcp.auth import AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.observability import (
    AlertBackend,
    AlertmanagerAlertBackend,
    InMemoryMetricsRegistry,
    PrometheusTrendBackend,
    TrendBackend,
)
from proxmox_mcp.proxmox import (
    ProxmoxApiClient,
    register_dangerous_tools,
    register_domain_completion_tools,
    register_helper_script_tools,
    register_media_tools,
    register_read_only_tools,
    register_safe_mutation_tools,
)
from proxmox_mcp.reliability import IdempotencyStore, ProxmoxTaskStore
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.security import ApprovalConsumer, SecurityPlaneGuard
from proxmox_mcp.server.auth_middleware import attach_service_token_middleware
from proxmox_mcp.server.health import (
    DependencyChecker,
    ProductionStateDependencyChecker,
    build_liveness_payload,
    build_readiness_payload,
    default_dependency_checkers,
)
from proxmox_mcp.server.runtime import RuntimeBundle, build_runtime
from proxmox_mcp.server.tls import resolve_tls_config
from proxmox_mcp.ssh import (
    InMemorySshRecordingStore,
    SshClient,
    SshCommandPolicy,
    SshRecordingStore,
    SshSessionManager,
    SshSessionStore,
)
from proxmox_mcp.ssh.tools import register_ssh_tools
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.internal import (
    HEALTH_CHECK_DEFINITION,
    register_internal_tools,
)
from proxmox_mcp.tools.internal import (
    build_health_payload as _build_health_payload,
)
from proxmox_mcp.tools.registry import ToolRegistry


def build_health_payload(settings: Settings) -> dict[str, str | int]:
    return _build_health_payload(settings)


async def health_check(
    settings: Settings,
    audit_writer: AuditWriter,
) -> dict[str, str | int]:
    request = ToolRequest(
        request_id="health_check",
        correlation_id="health_check",
        actor=Actor(user_id="system", agent_id="system"),
        target=Target(resource_type="internal", resource_id="health"),
        options=RequestOptions(dry_run=True),
    )
    registry = ToolRegistry(guard=SecurityPlaneGuard())
    registry.register(HEALTH_CHECK_DEFINITION)
    response = await registry.execute(
        "health_check",
        request,
        ToolExecutionContext(request=request, settings=settings, audit_writer=audit_writer),
    )

    if isinstance(response, ToolErrorResponse):
        raise RuntimeError(response.error.message)

    return _unwrap_health_result(response)


def _unwrap_health_result(response: ToolResponse) -> dict[str, str | int]:
    raw_result: object = response.result
    if not isinstance(raw_result, dict):
        raise TypeError("health_check returned a non-mapping result")

    result = cast(dict[str, object], raw_result)
    status = result.get("status")
    service = result.get("service")
    environment = result.get("environment")
    port = result.get("port")
    if not (
        isinstance(status, str)
        and isinstance(service, str)
        and isinstance(environment, str)
        and isinstance(port, int)
    ):
        raise TypeError("health_check returned an invalid payload")

    return {
        "status": status,
        "service": service,
        "environment": environment,
        "port": port,
    }


def build_server(
    settings: Settings | None = None,
    audit_writer: AuditWriter | None = None,
    proxmox_client: ProxmoxApiClient | None = None,
    ssh_client: SshClient | None = None,
    ssh_command_policy: SshCommandPolicy | None = None,
    ssh_session_manager: SshSessionManager | None = None,
    ssh_session_store: SshSessionStore | None = None,
    ssh_recording_store: SshRecordingStore | None = None,
    metrics_registry: InMemoryMetricsRegistry | None = None,
    alert_backend: AlertBackend | None = None,
    trend_backend: TrendBackend | None = None,
    dependency_checkers: Mapping[str, DependencyChecker] | None = None,
    audit_repository: AuditEventRepository | None = None,
    idempotency_store: IdempotencyStore | None = None,
    proxmox_task_store: ProxmoxTaskStore | None = None,
    authenticated_session_resolver: Callable[[ToolRequest], AuthenticatedSession | None]
    | None = None,
    approval_store: ApprovalConsumer | None = None,
) -> FastMCP:
    settings = Settings() if settings is None else settings
    audit_writer = InMemoryAuditWriter() if audit_writer is None else audit_writer
    ssh_command_policy = SshCommandPolicy() if ssh_command_policy is None else ssh_command_policy
    ssh_session_manager = (
        SshSessionManager() if ssh_session_manager is None else ssh_session_manager
    )
    ssh_recording_store = (
        InMemorySshRecordingStore() if ssh_recording_store is None else ssh_recording_store
    )
    metrics_registry = InMemoryMetricsRegistry() if metrics_registry is None else metrics_registry
    if alert_backend is None and settings.observability.alertmanager_url is not None:
        alert_backend = AlertmanagerAlertBackend(base_url=settings.observability.alertmanager_url)
    if trend_backend is None and settings.observability.prometheus_url is not None:
        trend_backend = PrometheusTrendBackend(base_url=settings.observability.prometheus_url)

    runtime_dependency_checkers = dependency_checkers
    if runtime_dependency_checkers is None:
        runtime_dependency_checkers = _runtime_dependency_checkers(
            audit_writer=audit_writer,
            ssh_session_store=ssh_session_store,
            ssh_recording_store=ssh_recording_store,
            idempotency_store=idempotency_store,
            proxmox_task_store=proxmox_task_store,
            approval_store=approval_store,
        )

    app = FastMCP("Enterprise Proxmox MCP")
    registry = ToolRegistry(
        guard=SecurityPlaneGuard(approval_store=approval_store),
        metrics_sink=metrics_registry,
    )
    register_internal_tools(registry)
    register_read_only_tools(registry)
    register_safe_mutation_tools(registry)
    register_dangerous_tools(registry)
    register_domain_completion_tools(registry)
    register_media_tools(registry)
    register_helper_script_tools(registry)
    register_ssh_tools(registry)

    def context_factory(request: ToolRequest) -> ToolExecutionContext:
        return build_tool_context(
            request,
            settings=settings,
            audit_writer=audit_writer,
            proxmox_client=proxmox_client,
            ssh_client=ssh_client,
            ssh_command_policy=ssh_command_policy,
            ssh_session_manager=ssh_session_manager,
            ssh_session_store=ssh_session_store,
            ssh_recording_store=ssh_recording_store,
            audit_repository=audit_repository,
            metrics_registry=metrics_registry,
            alert_backend=alert_backend,
            trend_backend=trend_backend,
            idempotency_store=idempotency_store,
            proxmox_task_store=proxmox_task_store,
            authenticated_session=authenticated_session_resolver(request)
            if authenticated_session_resolver is not None
            else None,
        )

    registry.register_with_fastmcp(app, context_factory)
    _register_http_routes(
        app,
        settings=settings,
        metrics_registry=metrics_registry,
        dependency_checkers=runtime_dependency_checkers,
    )
    return app


def _runtime_dependency_checkers(
    *,
    audit_writer: AuditWriter,
    ssh_session_store: SshSessionStore | None,
    ssh_recording_store: SshRecordingStore,
    idempotency_store: IdempotencyStore | None,
    proxmox_task_store: ProxmoxTaskStore | None,
    approval_store: ApprovalConsumer | None,
) -> Mapping[str, DependencyChecker]:
    checkers = dict(default_dependency_checkers())
    checkers["production_state"] = ProductionStateDependencyChecker(
        durable_components_configured=(
            not isinstance(audit_writer, InMemoryAuditWriter)
            and ssh_session_store is not None
            and not isinstance(ssh_recording_store, InMemorySshRecordingStore)
            and idempotency_store is not None
            and proxmox_task_store is not None
        ),
        approval_store_configured=approval_store is not None,
    )
    return checkers


def build_tool_context(
    request: ToolRequest,
    *,
    settings: Settings,
    audit_writer: AuditWriter,
    proxmox_client: ProxmoxApiClient | None = None,
    ssh_client: SshClient | None = None,
    ssh_command_policy: SshCommandPolicy | None = None,
    ssh_session_manager: SshSessionManager | None = None,
    ssh_session_store: SshSessionStore | None = None,
    ssh_recording_store: SshRecordingStore | None = None,
    audit_repository: AuditEventRepository | None = None,
    metrics_registry: InMemoryMetricsRegistry | None = None,
    alert_backend: AlertBackend | None = None,
    trend_backend: TrendBackend | None = None,
    idempotency_store: IdempotencyStore | None = None,
    proxmox_task_store: ProxmoxTaskStore | None = None,
    authenticated_session: AuthenticatedSession | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=settings,
        audit_writer=audit_writer,
        authenticated_session=authenticated_session,
        proxmox_client=proxmox_client,
        ssh_client=ssh_client,
        ssh_command_policy=ssh_command_policy,
        ssh_session_manager=ssh_session_manager,
        ssh_session_store=ssh_session_store,
        ssh_recording_store=ssh_recording_store,
        audit_repository=audit_repository,
        metrics_registry=metrics_registry,
        alert_backend=alert_backend,
        trend_backend=trend_backend,
        idempotency_store=idempotency_store,
        proxmox_task_store=proxmox_task_store,
    )


def _register_http_routes(
    app: FastMCP,
    *,
    settings: Settings,
    metrics_registry: InMemoryMetricsRegistry,
    dependency_checkers: Mapping[str, DependencyChecker] | None,
) -> None:
    @app.custom_route("/health/live", methods=["GET"], include_in_schema=False)
    async def live(request: Request) -> Response:
        _ = request
        return JSONResponse(build_liveness_payload(settings).model_dump(mode="json"))

    @app.custom_route("/health/ready", methods=["GET"], include_in_schema=False)
    async def ready(request: Request) -> Response:
        _ = request
        payload = await build_readiness_payload(settings, dependency_checkers)
        status_code = 200 if payload.status == "ready" else 503
        return JSONResponse(payload.model_dump(mode="json"), status_code=status_code)

    @app.custom_route("/metrics", methods=["GET"], include_in_schema=False)
    async def metrics(request: Request) -> Response:
        _ = request
        return PlainTextResponse(
            metrics_registry.render_prometheus(),
            media_type="text/plain; version=0.0.4",
        )

    _ = live, ready, metrics


def build_server_from_runtime(bundle: RuntimeBundle) -> FastMCP:
    return build_server(
        settings=bundle.settings,
        audit_writer=bundle.audit_writer,
        audit_repository=bundle.audit_repository,
        approval_store=bundle.approval_store,
        idempotency_store=bundle.idempotency_store,
        proxmox_task_store=bundle.proxmox_task_store,
        ssh_session_store=bundle.ssh_session_store,
        ssh_recording_store=bundle.ssh_recording_store,
        proxmox_client=bundle.proxmox_client,
        ssh_client=bundle.ssh_client,
        authenticated_session_resolver=bundle.authenticated_session_resolver,
        dependency_checkers=bundle.dependency_checkers,
    )


def run(settings: Settings | None = None, *, mode: str | None = None) -> None:
    settings = Settings() if settings is None else settings
    effective_mode = mode
    if effective_mode is None:
        effective_mode = "homelab" if settings.durable_state_enabled else "dev"

    if effective_mode == "homelab":
        bundle = build_runtime(settings)
        app = build_server_from_runtime(bundle)
    else:
        app = build_server(settings)

    attach_service_token_middleware(app, settings=settings)
    tls_config = resolve_tls_config(settings.tls)
    app.run(
        transport="http",
        host=settings.server_host,
        port=settings.server_port,
        log_level=settings.log_level,
        uvicorn_config=tls_config.uvicorn_config,
    )
