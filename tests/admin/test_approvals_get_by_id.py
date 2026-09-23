from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from starlette.testclient import TestClient

from proxmox_mcp.admin.app import AdminAppState, create_admin_starlette_app
from proxmox_mcp.admin.auth.providers import AdminIdentity, AdminSession
from proxmox_mcp.admin.config_store import ConfigStore, RuntimeController
from proxmox_mcp.admin.events import AdminEventHub
from proxmox_mcp.approvals import InMemoryApprovalStore
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.config import Settings
from proxmox_mcp.schemas.envelope import Target


def _homelab_settings(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Settings:
    env_file = tmp_path / ".env"
    env_file.write_text("PROXMOX_MCP_LOG_LEVEL=info\n", encoding="utf-8")
    monkeypatch.setenv("PROXMOX_MCP_ENV_FILE", str(env_file))
    monkeypatch.setenv("PROXMOX_MCP_ENVIRONMENT", "homelab")
    monkeypatch.setenv("PROXMOX_MCP_AUTH_MODE", "service_token")
    monkeypatch.setenv("PROXMOX_MCP_SERVICE_TOKEN", "x" * 32)
    monkeypatch.setenv("PROXMOX_MCP_LOG_LEVEL", "info")
    monkeypatch.setenv(
        "PROXMOX_MCP_DATABASE_URL",
        "postgresql+asyncpg://proxmox_mcp:proxmox_mcp@localhost/proxmox_mcp?ssl=require",
    )
    monkeypatch.setenv("PROXMOX_MCP_REDIS_URL", "rediss://localhost:6379/0")
    return Settings()


class _MemoryProvider:
    def __init__(self, *, role: str = "admin") -> None:
        self._sessions: dict[str, AdminSession] = {}
        self._user = AdminIdentity(user_id="adminuser_1", username="admin", role=role)  # type: ignore[arg-type]
        self._password = "secret123"

    async def authenticate(self, username: str, password: str) -> AdminIdentity | None:
        if username == "admin" and password == self._password:
            return self._user
        return None

    async def create_session(self, identity: AdminIdentity) -> AdminSession:
        session = AdminSession(
            session_id="adminsess_test",
            csrf_token="csrf_test",
            identity=identity,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        self._sessions[session.session_id] = session
        return session

    async def get_session(self, session_id: str) -> AdminSession | None:
        return self._sessions.get(session_id)

    async def revoke_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def ensure_bootstrap_user(self, username: str, password: str) -> None:
        _ = username, password

    async def verify_user_password(self, user_id: str, password: str) -> bool:
        return user_id == self._user.user_id and password == self._password


class Repo:
    async def list_events(self, **_kwargs: object) -> list[dict[str, object]]:
        return []

    async def get_event(self, _event_id: str) -> dict[str, object] | None:
        return None


def _client(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    role: str = "admin",
) -> tuple[TestClient, InMemoryApprovalStore]:
    settings = _homelab_settings(monkeypatch, tmp_path)
    provider = _MemoryProvider(role=role)
    store = ConfigStore(settings)
    approvals = InMemoryApprovalStore()
    state = AdminAppState(
        settings=settings,
        identity_provider=provider,  # type: ignore[arg-type]
        config_store=store,
        runtime=RuntimeController(store),
        audit_repository=Repo(),  # type: ignore[arg-type]
        audit_writer=InMemoryAuditWriter(),
        event_hub=AdminEventHub(),
        dependency_checkers=None,
        spa_dir=None,
        approval_store=approvals,
    )
    app = create_admin_starlette_app(state)
    client = TestClient(app)
    login = client.post(
        "/admin/api/auth/login",
        json={"username": "admin", "password": "secret123"},
    )
    assert login.status_code == 200
    return client, approvals


@pytest.mark.asyncio
async def test_get_by_id_returns_redacted_summary_without_token() -> None:
    store = InMemoryApprovalStore()
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1")
    target = Target(resource_type="vm", resource_id="100")
    queued = await store.queue_pending(
        operation="vm.delete",
        target=target,
        input_payload={"force": True},
        actor=actor,
        risk_level="critical",
        risk_score=95,
        summary={"tool_name": "delete_vm"},
    )
    row = await store.get_by_id(queued.approval_request_id)
    assert row is not None
    assert row["approval_request_id"] == queued.approval_request_id
    assert row["operation"] == "vm.delete"
    assert "approval_token" not in row
    assert "approval_token_hash" not in row
    assert await store.get_by_id("missing") is None


def test_admin_get_approval_never_leaks_token(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, approvals = _client(tmp_path, monkeypatch)
    import asyncio

    approval_id = asyncio.run(
        approvals.queue_pending(
            operation="vm.delete",
            target=Target(resource_type="vm", resource_id="100"),
            input_payload={"force": True},
            actor=ActorIdentity(user_id="u1", agent_id="a1", tenant_id="t1"),
            risk_level="critical",
            risk_score=95,
            summary={"tool_name": "delete_vm"},
        )
    ).approval_request_id
    resp = client.get(f"/admin/api/approvals/{approval_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["approval"]["approval_request_id"] == approval_id
    assert "approval_token" not in body
    assert "approval_token" not in body["approval"]
    assert "token_hash" not in resp.text


def test_decide_response_includes_retry_hint(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, approvals = _client(tmp_path, monkeypatch)
    import asyncio

    approval_id = asyncio.run(
        approvals.queue_pending(
            operation="vm.delete",
            target=Target(resource_type="vm", resource_id="101"),
            input_payload={"force": True},
            actor=ActorIdentity(user_id="u1", agent_id="a1", tenant_id="t1"),
            risk_level="medium",
            risk_score=50,
        )
    ).approval_request_id
    resp = client.post(
        f"/admin/api/approvals/{approval_id}/decide",
        headers={"X-CSRF-Token": "csrf_test"},
        json={"decision": "approved", "password": "secret123", "reason": "ok"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approval_request_id"] == approval_id
    assert body["approval_token"]
    assert "retry_hint" in body
    assert body["expires_at"]
