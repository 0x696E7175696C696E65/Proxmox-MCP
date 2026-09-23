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
from proxmox_mcp.rbac.capability import CapabilityRole


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


class _FakeRoleStore:
    def __init__(self) -> None:
        self.roles: dict[str, CapabilityRole] = {
            "caprole_system_admin": CapabilityRole(
                role_id="caprole_system_admin",
                name="Administrator",
                granted_tools=frozenset({"*"}),
                system=True,
            ),
            "caprole_system_viewer": CapabilityRole(
                role_id="caprole_system_viewer",
                name="Viewer",
                granted_tools=frozenset({"list_nodes"}),
                system=True,
            ),
        }

    async def ensure_system_roles(self, **_kwargs: object) -> None:
        return None

    async def list_roles(self) -> list[CapabilityRole]:
        return list(self.roles.values())

    async def get(self, role_id: str) -> CapabilityRole | None:
        return self.roles.get(role_id)

    async def create(
        self,
        *,
        name: str,
        description: str,
        granted_tools: list[str],
        denied_tools: list[str],
        base_template: str | None,
        allow_star: bool,
    ) -> CapabilityRole:
        if "*" in granted_tools and not allow_star:
            raise ValueError("Granting '*' requires break-glass allow_star")
        role = CapabilityRole(
            role_id="caprole_custom_1",
            name=name,
            description=description,
            base_template=base_template,
            granted_tools=frozenset(granted_tools),
            denied_tools=frozenset(denied_tools),
        )
        self.roles[role.role_id] = role
        return role

    async def update(self, role_id: str, **kwargs: object) -> CapabilityRole:
        existing = self.roles[role_id]
        grants = kwargs.get("granted_tools")
        allow_star = bool(kwargs.get("allow_star", False))
        if grants is not None and "*" in grants and not allow_star:  # type: ignore[operator]
            raise ValueError("Granting '*' requires break-glass allow_star")
        updated = CapabilityRole(
            role_id=existing.role_id,
            name=str(kwargs.get("name") or existing.name),
            description=str(
                kwargs["description"] if kwargs.get("description") is not None else existing.description
            ),
            granted_tools=frozenset(grants) if grants is not None else existing.granted_tools,  # type: ignore[arg-type]
            denied_tools=(
                frozenset(kwargs["denied_tools"])  # type: ignore[arg-type]
                if kwargs.get("denied_tools") is not None
                else existing.denied_tools
            ),
            system=existing.system,
            version=existing.version + 1,
        )
        self.roles[role_id] = updated
        return updated

    async def delete(self, role_id: str) -> None:
        role = self.roles.get(role_id)
        if role is None:
            raise LookupError(role_id)
        if role.system:
            raise PermissionError("Cannot delete system roles")
        del self.roles[role_id]


class Repo:
    async def list_events(self, **_kwargs: object) -> list[dict[str, object]]:
        return []

    async def get_event(self, _event_id: str) -> dict[str, object] | None:
        return None


def _client(tmp_path, monkeypatch: pytest.MonkeyPatch, *, role: str = "admin") -> tuple[TestClient, _FakeRoleStore]:
    settings = _homelab_settings(monkeypatch, tmp_path)
    store = _FakeRoleStore()
    config_store = ConfigStore(settings)
    state = AdminAppState(
        settings=settings,
        identity_provider=_MemoryProvider(role=role),  # type: ignore[arg-type]
        audit_writer=InMemoryAuditWriter(),
        audit_repository=Repo(),  # type: ignore[arg-type]
        event_hub=AdminEventHub(),
        config_store=config_store,
        runtime=RuntimeController(config_store),
        capability_role_store=store,
        dependency_checkers=None,
        spa_dir=None,
    )
    app = create_admin_starlette_app(state)
    client = TestClient(app)
    login = client.post("/admin/api/auth/login", json={"username": "admin", "password": "secret123"})
    assert login.status_code == 200
    return client, store


def test_access_roles_list_requires_admin(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = _client(tmp_path, monkeypatch, role="viewer")
    resp = client.get("/admin/api/access/roles")
    assert resp.status_code == 403


def test_access_roles_list_and_star_rejected(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, store = _client(tmp_path, monkeypatch)
    listed = client.get("/admin/api/access/roles")
    assert listed.status_code == 200
    assert listed.json()["count"] >= 2

    csrf = client.cookies.get("admin_csrf") or "csrf_test"
    created = client.post(
        "/admin/api/access/roles",
        json={
            "name": "God",
            "granted_tools": ["*"],
            "denied_tools": [],
            "allow_star": False,
            "password": "secret123",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 400
    assert "break-glass" in created.json()["detail"]

    ok = client.post(
        "/admin/api/access/roles",
        json={
            "name": "Ops",
            "granted_tools": ["list_nodes", "start_vm"],
            "denied_tools": ["start_vm"],
            "password": "secret123",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert ok.status_code == 201
    body = ok.json()["role"]
    assert body["name"] == "Ops"
    assert "list_nodes" in body["granted_tools"]
    assert "start_vm" in body["denied_tools"]
    assert "caprole_custom_1" in store.roles
