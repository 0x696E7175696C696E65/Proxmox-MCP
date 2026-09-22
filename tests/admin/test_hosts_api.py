from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import MagicMock, patch
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from proxmox_mcp.admin.app import AdminAppState, create_admin_starlette_app
from proxmox_mcp.admin.auth.providers import AdminIdentity, AdminSession
from proxmox_mcp.admin.config_store import ConfigStore, RuntimeController
from proxmox_mcp.admin.events import AdminEventHub
from proxmox_mcp.admin.hosts_store import HostCatalogStore
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import ClusterCredentialRefSettings, ClusterSettings, Settings


@dataclass
class AdminClientBundle:
    client: TestClient
    csrf: str
    host_catalog: HostCatalogStore
    runtime: RuntimeController


class _MemoryProvider:
    def __init__(self) -> None:
        self._sessions: dict[str, AdminSession] = {}
        self._user = AdminIdentity(user_id="adminuser_1", username="admin", role="admin")

    async def authenticate(self, username: str, password: str) -> AdminIdentity | None:
        if username == "admin" and password == "secret123":
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
        return user_id == self._user.user_id and password == "secret123"


def _homelab_settings(tmp_path: Path, secrets_path: Path) -> Settings:
    return Settings.model_construct(
        environment="homelab",
        auth_mode="service_token",
        secrets_file=str(secrets_path),
        cluster=ClusterSettings(
            cluster_id="homelab",
            name="Homelab Proxmox",
            api_endpoint="https://192.168.10.137:8006",
            tls_verify=False,
            credential_ref=ClusterCredentialRefSettings(
                provider="development",
                path="clusters/homelab/proxmox-api",
            ),
        ),
    )


@pytest.fixture
def admin_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AdminClientBundle:
    env_file = tmp_path / ".env"
    env_file.write_text("PROXMOX_MCP_LOG_LEVEL=info\n", encoding="utf-8")
    monkeypatch.setenv("PROXMOX_MCP_ENV_FILE", str(env_file))

    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(
        json.dumps(
            {
                "clusters/homelab/proxmox-api": {
                    "auth_type": "api_token",
                    "token_id": "root@pam!mcp",
                    "token_secret": "secret-value",
                }
            }
        ),
        encoding="utf-8",
    )

    settings = _homelab_settings(tmp_path, secrets_path)
    config_store = ConfigStore(settings)
    hosts_path = tmp_path / "hosts.local.json"

    def secrets_loader() -> dict[str, dict[str, object]]:
        payload = json.loads(secrets_path.read_text(encoding="utf-8"))
        return {str(k): dict(v) for k, v in payload.items() if isinstance(v, dict)}

    host_catalog = HostCatalogStore(
        path=hosts_path,
        settings=settings,
        secrets_loader=secrets_loader,
        config_applier=config_store.apply_config,
    )
    restart_calls: list[int] = []
    runtime = RuntimeController(config_store, exit_fn=lambda code: restart_calls.append(code))

    class Repo:
        async def list_events(self, **_kwargs: object) -> list[dict[str, object]]:
            return []

        async def get_event(self, _event_id: str) -> dict[str, object] | None:
            return None

    state = AdminAppState(
        settings=settings,
        identity_provider=_MemoryProvider(),  # type: ignore[arg-type]
        config_store=config_store,
        runtime=runtime,
        audit_repository=Repo(),  # type: ignore[arg-type]
        audit_writer=InMemoryAuditWriter(),
        event_hub=AdminEventHub(),
        dependency_checkers=None,
        spa_dir=None,
        host_catalog=host_catalog,
    )
    client = TestClient(create_admin_starlette_app(state))
    login = client.post(
        "/admin/api/auth/login",
        json={"username": "admin", "password": "secret123"},
    )
    assert login.status_code == 200
    return AdminClientBundle(
        client=client,
        csrf=login.json()["csrf_token"],
        host_catalog=host_catalog,
        runtime=runtime,
    )


def test_list_hosts_seeds_and_returns_active(admin_bundle: AdminClientBundle) -> None:
    r = admin_bundle.client.get("/admin/api/hosts")
    assert r.status_code == 200
    body = r.json()
    assert body["active_host_id"] == "homelab"
    assert len(body["hosts"]) == 1
    assert body["hosts"][0]["host_id"] == "homelab"
    assert body["hosts"][0]["secrets_ready"] is True


def test_create_and_update_host(admin_bundle: AdminClientBundle) -> None:
    create = admin_bundle.client.post(
        "/admin/api/hosts",
        json={
            "host_id": "pve-b",
            "name": "PVE B",
            "api_endpoint": "https://192.168.10.200:8006",
            "tls_verify": True,
            "credential_ref_path": "clusters/pve-b/proxmox-api",
            "enabled": True,
        },
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    assert create.status_code == 201
    assert create.json()["host"]["host_id"] == "pve-b"

    update = admin_bundle.client.put(
        "/admin/api/hosts/pve-b",
        json={
            "host_id": "pve-b",
            "name": "PVE B Renamed",
            "api_endpoint": "https://192.168.10.201:8006",
            "tls_verify": False,
            "credential_ref_path": "clusters/pve-b/proxmox-api",
            "enabled": True,
        },
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    assert update.status_code == 200
    assert update.json()["host"]["name"] == "PVE B Renamed"


def test_delete_active_host_conflict(admin_bundle: AdminClientBundle) -> None:
    admin_bundle.client.get("/admin/api/hosts")
    delete = admin_bundle.client.delete(
        "/admin/api/hosts/homelab",
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    assert delete.status_code == 409


def test_activate_missing_secrets_no_restart(admin_bundle: AdminClientBundle) -> None:
    admin_bundle.client.get("/admin/api/hosts")
    admin_bundle.client.post(
        "/admin/api/hosts",
        json={
            "host_id": "pve-b",
            "name": "PVE B",
            "api_endpoint": "https://192.168.10.200:8006",
            "tls_verify": True,
            "credential_ref_path": "clusters/pve-b/proxmox-api",
            "enabled": True,
        },
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    calls: list[int] = []
    admin_bundle.runtime._exit_fn = lambda code: calls.append(code)  # noqa: SLF001

    r = admin_bundle.client.post(
        "/admin/api/hosts/pve-b/activate",
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    assert r.status_code == 400
    assert "secret" in r.json()["detail"].lower()
    assert calls == []


def test_activate_ok_restarts(admin_bundle: AdminClientBundle) -> None:
    import time

    admin_bundle.client.get("/admin/api/hosts")
    calls: list[int] = []
    admin_bundle.runtime._exit_fn = lambda code: calls.append(code)  # noqa: SLF001

    r = admin_bundle.client.post(
        "/admin/api/hosts/homelab/activate",
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["host_id"] == "homelab"
    assert body["restarting"] is True
    # Restart is deferred so the HTTP response can flush first.
    assert calls == []
    time.sleep(1.0)
    assert calls == [0]


def test_create_duplicate_host_returns_409(admin_bundle: AdminClientBundle) -> None:
    admin_bundle.client.get("/admin/api/hosts")
    payload = {
        "host_id": "homelab",
        "name": "Duplicate",
        "api_endpoint": "https://192.168.10.137:8006",
        "tls_verify": False,
        "credential_ref_path": "clusters/homelab/proxmox-api",
        "enabled": True,
    }
    r = admin_bundle.client.post(
        "/admin/api/hosts",
        json=payload,
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    assert r.status_code == 409
    assert "already exists" in r.json()["detail"].lower()


def test_probe_host_success(admin_bundle: AdminClientBundle) -> None:
    admin_bundle.client.get("/admin/api/hosts")
    version_body = json.dumps({"data": {"version": "8.3.0"}}).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = version_body
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("proxmox_mcp.admin.hosts.urlopen", return_value=mock_resp):
        r = admin_bundle.client.post(
            "/admin/api/hosts/homelab/probe",
            headers={"X-CSRF-Token": admin_bundle.csrf},
        )

    assert r.status_code == 200
    health = r.json()["health"]
    assert health["ok"] is True
    assert health["version"] == "8.3.0"
    assert isinstance(health.get("latency_ms"), int)


def test_probe_host_without_secrets(admin_bundle: AdminClientBundle) -> None:
    admin_bundle.client.get("/admin/api/hosts")
    admin_bundle.client.post(
        "/admin/api/hosts",
        json={
            "host_id": "pve-b",
            "name": "PVE B",
            "api_endpoint": "https://192.168.10.200:8006",
            "tls_verify": True,
            "credential_ref_path": "clusters/pve-b/proxmox-api",
            "enabled": True,
        },
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    r = admin_bundle.client.post(
        "/admin/api/hosts/pve-b/probe",
        headers={"X-CSRF-Token": admin_bundle.csrf},
    )
    assert r.status_code == 200
    health = r.json()["health"]
    assert health["ok"] is False
    assert health.get("error")


def test_hosts_mutations_require_csrf(admin_bundle: AdminClientBundle) -> None:
    r = admin_bundle.client.post(
        "/admin/api/hosts",
        json={
            "host_id": "pve-c",
            "name": "PVE C",
            "api_endpoint": "https://192.168.10.210:8006",
            "tls_verify": True,
            "credential_ref_path": "clusters/pve-c/proxmox-api",
        },
    )
    assert r.status_code == 403
