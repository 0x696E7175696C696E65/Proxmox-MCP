# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr

from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.audit.repository import DatabaseAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import ClusterCredentialRefSettings, ClusterSettings, Settings
from proxmox_mcp.proxmox.domain_tools import register_domain_completion_tools
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.server.app import build_server_from_runtime
from proxmox_mcp.server.runtime import build_runtime_async
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolRegistry


@pytest.fixture
def homelab_database_url(tmp_path: Path) -> str:
    database_path = tmp_path / "audit.db"
    database_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    alembic_config = Config("alembic.ini")
    alembic_config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(alembic_config, "head")
    return database_url


@pytest.mark.asyncio
async def test_get_audit_events_queries_durable_repository(
    tmp_path: Path,
    homelab_database_url: str,
) -> None:
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(
        json.dumps(
            {
                "clusters/homelab/proxmox-api": {
                    "auth_type": "api_token",
                    "token_id": "root@pam!mcp",
                    "token_secret": "token-secret",
                }
            }
        ),
        encoding="utf-8",
    )
    database_url = homelab_database_url

    settings = Settings.model_construct(
        environment="homelab",
        auth_mode="service_token",
        external_auth_enabled=True,
        durable_state_enabled=True,
        service_token=SecretStr("service-token"),
        secrets_file=str(secrets_path),
        database_url=SecretStr(database_url),
        redis_url=SecretStr("rediss://localhost:6379/0"),
        credential_provider="development",
        cluster=ClusterSettings(
            cluster_id="homelab",
            name="Homelab",
            api_endpoint="https://pve.example.test:8006",
            credential_ref=ClusterCredentialRefSettings(
                provider="development",
                path="clusters/homelab/proxmox-api",
            ),
        ),
    )
    bundle = await build_runtime_async(settings)
    now = datetime.now(UTC)
    await DatabaseAuditWriter(bundle.session_factory).write(
        AuditEvent(
            event_id="evt_1",
            timestamp=now,
            event_type="tool.execution",
            correlation_id="corr_1",
            tenant_id="tenant_1",
            actor_user_id="operator",
            actor_agent_id="agent",
            tool_name="health_check",
            operation="read",
            target=AuditTarget(resource_type="internal", resource_id="health"),
            result_status="success",
        )
    )

    registry = ToolRegistry(guard=SecurityPlaneGuard(approval_store=bundle.approval_store))
    register_domain_completion_tools(registry)
    session = AuthenticatedSession(
        session_id="sess_1",
        identity=ActorIdentity(user_id="operator", agent_id="agent", tenant_id="tenant_1"),
        auth_method="service_token",
        status="active",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    request = ToolRequest(
        request_id="req_1",
        correlation_id="corr_1",
        actor=Actor(user_id="operator", agent_id="agent", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            resource_type="internal",
            resource_id="audit",
        ),
        options=RequestOptions(dry_run=False),
        parameters={"payload": {"limit": 10}},
    )
    context = ToolExecutionContext(
        request=request,
        settings=settings,
        audit_writer=bundle.audit_writer,
        authenticated_session=session,
        audit_repository=bundle.audit_repository,
    )

    response = await registry.execute("get_audit_events", request, context)

    assert isinstance(response, ToolResponse)
    result = response.result
    assert isinstance(result, dict)
    events = result["result"]
    assert isinstance(events, list)
    assert any(event.get("event_id") == "evt_1" for event in events)

    _ = build_server_from_runtime(bundle)
