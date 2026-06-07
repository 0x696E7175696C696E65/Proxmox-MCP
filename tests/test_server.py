from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import ObservabilitySettings, Settings, TlsSettings
from proxmox_mcp.observability import InMemoryMetricsRegistry
from proxmox_mcp.proxmox import (
    DANGEROUS_TOOL_SPECS,
    DOMAIN_COMPLETION_TOOL_SPECS,
    READ_ONLY_TOOL_SPECS,
    SAFE_MUTATION_TOOL_SPECS,
)
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.server import app as app_module
from proxmox_mcp.server.app import (
    build_health_payload,
    build_server,
    build_tool_context,
    health_check,
)
from proxmox_mcp.server.health import (
    ConfiguredUrlDependencyChecker,
    ProductionAuthDependencyChecker,
    SecretBackendDependencyChecker,
    SiemDeliveryDependencyChecker,
    StaticDependencyChecker,
    build_liveness_payload,
    build_readiness_payload,
)
from proxmox_mcp.ssh.tools import SSH_TOOL_SPECS
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.internal import HEALTH_CHECK_DEFINITION
from proxmox_mcp.tools.registry import ToolRegistry


def test_health_payload_reports_runtime_status() -> None:
    payload = build_health_payload(Settings(environment="test"))

    assert payload["status"] == "ok"
    assert payload["service"] == "enterprise-proxmox-mcp"
    assert payload["environment"] == "test"
    assert payload["port"] == 8443


def test_liveness_payload_reports_process_status_without_dependency_checks() -> None:
    payload = build_liveness_payload(Settings(environment="test"))

    assert payload.status == "ok"
    assert payload.service == "enterprise-proxmox-mcp"
    assert payload.environment == "test"
    assert payload.port == 8443


async def test_readiness_payload_fails_closed_when_required_dependency_fails() -> None:
    payload = await build_readiness_payload(
        Settings(environment="test"),
        {
            "postgresql": StaticDependencyChecker(
                name="postgresql",
                required=True,
                status="unavailable",
                detail="connection refused",
            ),
            "redis": StaticDependencyChecker(
                name="redis",
                required=True,
                status="ok",
                detail="ping succeeded",
            ),
        },
    )

    assert payload.status == "not_ready"
    assert payload.dependencies["postgresql"].status == "unavailable"


async def test_readiness_payload_allows_optional_dependency_degradation() -> None:
    payload = await build_readiness_payload(
        Settings(environment="test"),
        {
            "postgresql": StaticDependencyChecker(
                name="postgresql",
                required=True,
                status="ok",
                detail="query succeeded",
            ),
            "external_alerts": StaticDependencyChecker(
                name="external_alerts",
                required=False,
                status="unavailable",
                detail="not configured",
            ),
        },
    )

    assert payload.status == "ready"
    assert payload.dependencies["external_alerts"].required is False


async def test_default_readiness_fails_when_required_alertmanager_is_missing() -> None:
    settings = Settings(
        environment="test",
        observability=ObservabilitySettings(alertmanager_required=True),
    )
    payload = await build_readiness_payload(
        settings,
        {
            "alertmanager": ConfiguredUrlDependencyChecker(
                name="alertmanager",
                settings_field="alertmanager_url",
                required_field="alertmanager_required",
            )
        },
    )

    assert payload.status == "not_ready"
    assert payload.dependencies["alertmanager"].required is True
    assert payload.dependencies["alertmanager"].status == "unavailable"


async def test_default_readiness_fails_when_required_siem_delivery_is_missing() -> None:
    settings = Settings(
        environment="test",
        observability=ObservabilitySettings(siem_required=True),
    )
    payload = await build_readiness_payload(
        settings,
        {"siem_delivery": SiemDeliveryDependencyChecker()},
    )

    assert payload.status == "not_ready"
    assert payload.dependencies["siem_delivery"].required is True
    assert payload.dependencies["siem_delivery"].status == "unavailable"


async def test_readiness_accepts_configured_required_siem_delivery() -> None:
    settings = Settings(
        environment="test",
        observability=ObservabilitySettings(siem_required=True),
    )
    payload = await build_readiness_payload(
        settings,
        {"siem_delivery": SiemDeliveryDependencyChecker(configured=True)},
    )

    assert payload.status == "ready"
    assert payload.dependencies["siem_delivery"].required is True
    assert payload.dependencies["siem_delivery"].status == "ok"


async def test_secret_backend_readiness_fails_closed_for_missing_provider_config() -> None:
    payload = await build_readiness_payload(
        Settings(environment="test", credential_provider="bitwarden"),
        {"secret_backend": SecretBackendDependencyChecker()},
    )

    assert payload.status == "not_ready"
    assert payload.dependencies["secret_backend"].status == "unavailable"
    assert "bitwarden" in payload.dependencies["secret_backend"].detail


async def test_secret_backend_readiness_rejects_development_provider_in_production() -> None:
    payload = await build_readiness_payload(
        Settings(environment="production", credential_provider="development"),
        {"secret_backend": SecretBackendDependencyChecker()},
    )

    assert payload.status == "not_ready"
    assert payload.dependencies["secret_backend"].status == "unavailable"
    assert "not allowed in production" in payload.dependencies["secret_backend"].detail


async def test_secret_backend_readiness_accepts_configured_enterprise_provider() -> None:
    payload = await build_readiness_payload(
        Settings(
            environment="test",
            credential_provider="aws_secrets_manager",
            aws_region="us-east-1",
        ),
        {"secret_backend": SecretBackendDependencyChecker()},
    )

    assert payload.status == "ready"
    assert payload.dependencies["secret_backend"].status == "ok"
    assert payload.dependencies["secret_backend"].detail == (
        "aws_secrets_manager provider configured"
    )


async def test_production_readiness_rejects_development_auth_mode() -> None:
    payload = await build_readiness_payload(
        Settings(environment="production", auth_mode="development"),
        {"auth": ProductionAuthDependencyChecker()},
    )

    assert payload.status == "not_ready"
    assert payload.dependencies["auth"].status == "unavailable"
    assert "development auth mode" in payload.dependencies["auth"].detail


async def test_production_readiness_requires_external_auth_resolver_path() -> None:
    payload = await build_readiness_payload(
        Settings(environment="production", auth_mode="oidc", external_auth_enabled=False),
        {"auth": ProductionAuthDependencyChecker()},
    )

    assert payload.status == "not_ready"
    assert payload.dependencies["auth"].status == "unavailable"
    assert "external authenticated session resolver" in payload.dependencies["auth"].detail


async def test_production_readiness_accepts_external_auth_path() -> None:
    payload = await build_readiness_payload(
        Settings(environment="production", auth_mode="oidc", external_auth_enabled=True),
        {"auth": ProductionAuthDependencyChecker()},
    )

    assert payload.status == "ready"
    assert payload.dependencies["auth"].status == "ok"


def test_build_server_returns_named_app() -> None:
    app = build_server(Settings(environment="test"), InMemoryAuditWriter())

    assert app.name == "Enterprise Proxmox MCP"


def test_build_server_registers_health_and_metrics_routes() -> None:
    metrics = InMemoryMetricsRegistry()
    app = build_server(
        Settings(environment="test"),
        InMemoryAuditWriter(),
        metrics_registry=metrics,
        dependency_checkers={
            "postgresql": StaticDependencyChecker(
                name="postgresql",
                required=True,
                status="ok",
                detail="query succeeded",
            )
        },
    )

    routes = app._get_additional_http_routes()  # pyright: ignore[reportPrivateUsage]
    paths = {cast(Any, route).path for route in routes}

    assert {"/health/live", "/health/ready", "/metrics"} <= paths


def test_run_starts_fastmcp_with_https_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    class RecordingApp:
        def run(self, **kwargs: object) -> None:
            captured.update(kwargs)

    def fake_build_server(settings: Settings) -> RecordingApp:
        _ = settings
        return RecordingApp()

    monkeypatch.setattr(app_module, "build_server", fake_build_server)

    app_module.run(
        Settings(
            environment="test",
            tls=TlsSettings(
                generate_self_signed=True,
                generated_cert_dir=str(tmp_path),
            ),
        )
    )

    assert captured["transport"] == "http"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8443
    assert captured["log_level"] == "info"
    assert captured["uvicorn_config"] == {
        "ssl_certfile": str(tmp_path / "proxmox-mcp.crt"),
        "ssl_keyfile": str(tmp_path / "proxmox-mcp.key"),
    }


async def test_build_server_registers_health_and_read_only_tools() -> None:
    app = build_server(Settings(environment="test"), InMemoryAuditWriter())

    tools = await app.list_tools()

    tool_names = [tool.name for tool in tools]
    assert tool_names[0] == "health_check"
    assert set(tool_names[1:]) == {spec.name for spec in READ_ONLY_TOOL_SPECS} | {
        spec.name for spec in SAFE_MUTATION_TOOL_SPECS
    } | {spec.name for spec in DANGEROUS_TOOL_SPECS} | {
        spec.name for spec in DOMAIN_COMPLETION_TOOL_SPECS
    } | {spec.name for spec in SSH_TOOL_SPECS}


def test_build_tool_context_accepts_resolved_authenticated_session() -> None:
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    session = AuthenticatedSession(
        session_id="sess_1",
        identity=ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        auth_method="oidc_jwt",
        status="active",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    request = ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(resource_type="internal", resource_id="health"),
        options=RequestOptions(dry_run=True),
    )

    context = build_tool_context(
        request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        authenticated_session=session,
    )

    assert context.authenticated_session == session


async def test_health_check_writes_audit_event() -> None:
    writer = InMemoryAuditWriter()

    payload = await health_check(Settings(environment="test"), writer)

    assert payload["status"] == "ok"
    assert len(writer.events) == 2

    started_event = writer.events[0]
    success_event = writer.events[1]

    assert started_event.result_status == "started"
    assert success_event.result_status == "success"

    for event in writer.events:
        assert event.tool_name == "health_check"
        assert event.operation == "internal.health.read"
        assert event.target.resource_type == "internal"
        assert event.target.resource_id == "health"
        assert event.actor_user_id == "system"
        assert event.actor_agent_id == "system"
        assert event.correlation_id == "health_check"


async def test_legacy_health_check_uses_registry_audit_metadata() -> None:
    settings = Settings(environment="test")
    legacy_writer = InMemoryAuditWriter()
    registry_writer = InMemoryAuditWriter()
    registry = ToolRegistry()
    registry.register(HEALTH_CHECK_DEFINITION)
    request = ToolRequest(
        request_id="health_check",
        correlation_id="health_check",
        actor=Actor(user_id="system", agent_id="system"),
        target=Target(resource_type="internal", resource_id="health"),
        options=RequestOptions(dry_run=True),
    )

    legacy_payload = await health_check(settings, legacy_writer)
    registry_response = await registry.execute(
        "health_check",
        request,
        ToolExecutionContext(
            request=request,
            settings=settings,
            audit_writer=registry_writer,
        ),
    )

    assert isinstance(registry_response, ToolResponse)
    assert legacy_payload == registry_response.result
    assert [
        event.model_dump(exclude={"event_id", "timestamp"}) for event in legacy_writer.events
    ] == [event.model_dump(exclude={"event_id", "timestamp"}) for event in registry_writer.events]
