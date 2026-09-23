from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from proxmox_mcp.admin.app import AdminAppState, create_admin_starlette_app
from proxmox_mcp.admin.auth.passwords import hash_password, verify_password
from proxmox_mcp.admin.auth.providers import AdminIdentity, AdminSession
from proxmox_mcp.admin.config_store import AdminConfigUpdate, ConfigStore, RuntimeController
from proxmox_mcp.admin.events import AdminEventHub
from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.audit.repository import PublishingAuditWriter
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings


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


def test_password_hash_roundtrip() -> None:
    hashed = hash_password("correct-horse")
    assert verify_password(hashed, "correct-horse")
    assert not verify_password(hashed, "wrong")


def test_config_store_hot_apply_log_level(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _homelab_settings(monkeypatch, tmp_path)
    store = ConfigStore(settings)
    result = store.apply_config(AdminConfigUpdate(log_level="debug"))
    assert result.kind == "hot"
    assert "log_level" in result.changed_fields
    env_file = tmp_path / ".env"
    assert "PROXMOX_MCP_LOG_LEVEL=debug" in env_file.read_text(encoding="utf-8")


def test_runtime_controller_uses_exit_fn(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    settings = _homelab_settings(monkeypatch, tmp_path)
    store = ConfigStore(settings)
    store.require_restart("token rotated")
    controller = RuntimeController(store, exit_fn=lambda code: calls.append(code))
    # Boot clears restart_required via mark_restarted in __init__.
    assert store.restart_required is False
    store.require_restart("token rotated")
    controller.request_restart(delay_seconds=0)
    assert calls == [0]
    # request_restart must not clear restart_required before process death.
    assert store.restart_required is True


def test_runtime_controller_defers_exit(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    settings = _homelab_settings(monkeypatch, tmp_path)
    store = ConfigStore(settings)
    controller = RuntimeController(store, exit_fn=lambda code: calls.append(code))
    status = controller.request_restart(delay_seconds=0.05)
    assert status["restart_requested"] is True
    assert calls == []
    import time

    time.sleep(0.15)
    assert calls == [0]


def test_publishing_audit_writer_emits_event() -> None:
    hub = AdminEventHub()
    writer = PublishingAuditWriter(InMemoryAuditWriter(), hub)

    async def _run() -> dict[str, object]:
        async def consume() -> dict[str, object]:
            async for item in hub.subscribe():
                return item
            raise AssertionError("no event")

        task = asyncio.create_task(consume())
        await asyncio.sleep(0)
        await writer.write(
            AuditEvent(
                event_type="tool",
                correlation_id="c1",
                actor_user_id="u",
                actor_agent_id="a",
                tool_name="list_nodes",
                operation="list",
                target=AuditTarget(resource_type="cluster", resource_id="homelab"),
                result_status="success",
            )
        )
        return await asyncio.wait_for(task, timeout=2)

    event = asyncio.run(_run())
    assert event["type"] == "audit.created"


class _MemoryProvider:
    def __init__(self) -> None:
        self._sessions: dict[str, AdminSession] = {}
        self._user = AdminIdentity(user_id="adminuser_1", username="admin", role="admin")
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


def test_admin_login_csrf_and_config(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _homelab_settings(monkeypatch, tmp_path)
    provider = _MemoryProvider()
    store = ConfigStore(settings)

    class Repo:
        async def list_events(self, **_kwargs: object) -> list[dict[str, object]]:
            return []

        async def get_event(self, _event_id: str) -> dict[str, object] | None:
            return None

    state = AdminAppState(
        settings=settings,
        identity_provider=provider,  # type: ignore[arg-type]
        config_store=store,
        runtime=RuntimeController(store, exit_fn=lambda _code: None),
        audit_repository=Repo(),  # type: ignore[arg-type]
        audit_writer=InMemoryAuditWriter(),
        event_hub=AdminEventHub(),
        dependency_checkers=None,
        spa_dir=None,
    )

    app = create_admin_starlette_app(state)
    client = TestClient(app)
    assert client.get("/admin/api/me").status_code == 401

    login = client.post(
        "/admin/api/auth/login",
        json={"username": "admin", "password": "secret123"},
    )
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    set_cookie = login.headers.get("set-cookie", "")
    assert "proxmox_mcp_admin_session=" in set_cookie
    assert "Path=/admin" in set_cookie or "path=/admin" in set_cookie.lower()
    assert client.get("/admin/api/me").status_code == 200

    audit = client.get("/admin/api/audit")
    assert audit.status_code == 200
    assert "events" in audit.json()

    assert client.put("/admin/api/config", json={"log_level": "debug"}).status_code == 403
    ok = client.put(
        "/admin/api/config",
        json={"log_level": "warning"},
        headers={"X-CSRF-Token": csrf},
    )
    assert ok.status_code == 200
    assert ok.json()["result"]["kind"] == "hot"

    # Tools registry absent → 503; policy still works via ConfigStore.
    tools = client.get("/admin/api/tools")
    assert tools.status_code == 503
    policy = client.get("/admin/api/policy")
    assert policy.status_code == 200
    assert "dangerous_operations" in policy.json()
    policy_put = client.put(
        "/admin/api/policy",
        json={
            "dangerous_operations_require_approval": True,
            "password": "secret123",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert policy_put.status_code == 200

    settings = Settings(
        environment="homelab",
        auth_mode="service_token",
        service_token=SecretStr("y" * 32),
        admin_username="admin",
        admin_password=SecretStr("bootstrap-pass"),
        admin_spa_dir="web/dist",
    )
    assert settings.admin_username == "admin"
    assert settings.admin_spa_dir == "web/dist"
