from __future__ import annotations

from datetime import UTC, datetime, timedelta

import asyncio

import pytest
from starlette.testclient import TestClient

from proxmox_mcp.admin.app import AdminAppState, create_admin_starlette_app
from proxmox_mcp.admin.auth.providers import AdminIdentity, AdminSession
from proxmox_mcp.admin.config_store import ConfigStore, RuntimeController
from proxmox_mcp.admin.events import AdminEventHub
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.reliability import InMemoryProxmoxTaskStore


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


@pytest.mark.asyncio
async def test_task_store_list_and_refresh_status() -> None:
    store = InMemoryProxmoxTaskStore()
    await store.record_task(
        upid="UPID:node1:0001:1:task:",
        operation="vm.start",
        method="POST",
        endpoint="/nodes/node1/qemu/100/status/start",
        target={"node": "node1", "vmid": 100},
        request_fingerprint="abc",
        idempotency_key=None,
    )
    listed = await store.list_tasks(limit=10)
    assert len(listed) == 1
    updated = await store.update_observed_state(
        "UPID:node1:0001:1:task:",
        status="stopped",
        last_observed_state="OK",
    )
    assert updated.status == "stopped"
    assert updated.last_observed_state == "OK"


def test_admin_tasks_list_authz(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _homelab_settings(monkeypatch, tmp_path)
    store = InMemoryProxmoxTaskStore()
    asyncio.run(
        store.record_task(
            upid="UPID:n1:1:1:t:",
            operation="vm.start",
            method="POST",
            endpoint="/nodes/n1/qemu/1/status/start",
            target={"node": "n1"},
            request_fingerprint="x",
            idempotency_key=None,
        )
    )
    state = AdminAppState(
        settings=settings,
        identity_provider=_MemoryProvider(role="operator"),  # type: ignore[arg-type]
        config_store=ConfigStore(settings),
        runtime=RuntimeController(ConfigStore(settings)),
        audit_repository=Repo(),  # type: ignore[arg-type]
        audit_writer=InMemoryAuditWriter(),
        event_hub=AdminEventHub(),
        dependency_checkers=None,
        spa_dir=None,
        proxmox_task_store=store,
    )
    client = TestClient(create_admin_starlette_app(state))
    login = client.post("/admin/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert login.status_code == 200
    resp = client.get("/admin/api/tasks")
    assert resp.status_code == 200
    assert resp.json()["count"] == 1


def test_viewer_cannot_refresh_tasks(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _homelab_settings(monkeypatch, tmp_path)
    store = InMemoryProxmoxTaskStore()
    asyncio.run(
        store.record_task(
            upid="UPID:n1:1:1:t:",
            operation="vm.start",
            method="POST",
            endpoint="/x",
            target={"node": "n1"},
            request_fingerprint="x",
            idempotency_key=None,
        )
    )
    state = AdminAppState(
        settings=settings,
        identity_provider=_MemoryProvider(role="viewer"),  # type: ignore[arg-type]
        config_store=ConfigStore(settings),
        runtime=RuntimeController(ConfigStore(settings)),
        audit_repository=Repo(),  # type: ignore[arg-type]
        audit_writer=InMemoryAuditWriter(),
        event_hub=AdminEventHub(),
        dependency_checkers=None,
        spa_dir=None,
        proxmox_task_store=store,
    )
    client = TestClient(create_admin_starlette_app(state))
    login = client.post("/admin/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert login.status_code == 200
    denied = client.post(
        "/admin/api/tasks/UPID:n1:1:1:t:/refresh",
        headers={"X-CSRF-Token": "csrf_test"},
    )
    assert denied.status_code == 403
