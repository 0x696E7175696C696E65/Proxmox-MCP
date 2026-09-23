from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from starlette.testclient import TestClient

from proxmox_mcp.admin.app import AdminAppState, create_admin_starlette_app
from proxmox_mcp.admin.auth.providers import AdminIdentity, AdminSession
from proxmox_mcp.admin.config_store import ConfigStore, RuntimeController
from proxmox_mcp.admin.events import AdminEventHub
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


def test_inventory_summary_fail_closed_without_client(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _homelab_settings(monkeypatch, tmp_path)
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
        proxmox_client=None,
    )
    client = TestClient(create_admin_starlette_app(state))
    login = client.post("/admin/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert login.status_code == 200
    resp = client.get("/admin/api/inventory/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False


class _FakeProxmox:
    async def get(self, path: str) -> object:
        if path == "/nodes":
            return [{"node": "pve1", "status": "online"}]
        if path == "/nodes/pve1/status":
            return {
                "cpu": 0.25,
                "maxcpu": 8,
                "mem": 4_000_000_000,
                "maxmem": 16_000_000_000,
                "uptime": 3600,
                "pveversion": "pve-manager/8.2",
            }
        if path == "/nodes/pve1/qemu":
            return [
                {
                    "vmid": 100,
                    "name": "web",
                    "status": "running",
                    "cpu": 0.1,
                    "mem": 512_000_000,
                    "maxmem": 2_000_000_000,
                    "disk": 10_000_000_000,
                    "maxdisk": 40_000_000_000,
                    "uptime": 120,
                    "tags": "prod;web",
                }
            ]
        if path == "/nodes/pve1/lxc":
            return []
        if path == "/nodes/pve1/storage":
            return [
                {
                    "storage": "local",
                    "type": "dir",
                    "used": 50,
                    "total": 100,
                    "content": "images,iso",
                    "active": 1,
                }
            ]
        if path == "/nodes/pve1/qemu/100/status/current":
            return {"status": "running", "cpu": 0.1, "mem": 512_000_000, "maxmem": 2_000_000_000}
        if path == "/nodes/pve1/qemu/100/config":
            return {"name": "web", "cores": 2, "cipassword": "secret", "sshkeys": "ssh-rsa AAAA"}
        raise KeyError(path)


def test_inventory_summary_enriched_fields(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _homelab_settings(monkeypatch, tmp_path)
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
        proxmox_client=_FakeProxmox(),
    )
    client = TestClient(create_admin_starlette_app(state))
    login = client.post("/admin/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert login.status_code == 200
    resp = client.get("/admin/api/inventory/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is True
    node = body["nodes"][0]
    assert node["cpu_percent"] == 25.0
    assert node["mem_percent"] == 25.0
    assert node["uptime_seconds"] == 3600
    assert "pve-manager" in str(node["version"])
    vm = body["vms"][0]
    assert vm["cpu_percent"] == 10.0
    assert vm["mem_percent"] == 25.6 or abs(float(vm["mem_percent"]) - 25.6) < 0.1
    assert vm["tags"] == ["prod", "web"]
    store = body["storage"][0]
    assert store["used_percent"] == 50.0
    assert "images" in store["content_types"]


def test_inventory_guest_detail_redacts_secrets(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _homelab_settings(monkeypatch, tmp_path)
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
        proxmox_client=_FakeProxmox(),
    )
    client = TestClient(create_admin_starlette_app(state))
    login = client.post("/admin/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert login.status_code == 200
    resp = client.get("/admin/api/inventory/guests/vm/100?node=pve1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is True
    assert body["config_summary"]["cipassword"] in {"[redacted]", "**********"}
    assert body["config_summary"]["sshkeys"] in {"[redacted]", "**********"}
    assert body["config_summary"]["name"] == "web"


def test_observability_overview_unconfigured(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _homelab_settings(monkeypatch, tmp_path)
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
    )
    client = TestClient(create_admin_starlette_app(state))
    login = client.post("/admin/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert login.status_code == 200
    resp = client.get("/admin/api/observability/overview")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert "token" not in resp.text.lower() or "alertmanager" in resp.text.lower()
