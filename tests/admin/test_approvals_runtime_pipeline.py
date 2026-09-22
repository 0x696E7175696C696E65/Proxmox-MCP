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
    exit_calls: list[int] | None = None,
) -> tuple[TestClient, InMemoryApprovalStore, ConfigStore]:
    settings = _homelab_settings(monkeypatch, tmp_path)
    provider = _MemoryProvider(role=role)
    store = ConfigStore(settings)
    approvals = InMemoryApprovalStore()
    calls = exit_calls if exit_calls is not None else []
    state = AdminAppState(
        settings=settings,
        identity_provider=provider,  # type: ignore[arg-type]
        config_store=store,
        runtime=RuntimeController(store, exit_fn=lambda code: calls.append(code)),
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
    return client, approvals, store


@pytest.mark.asyncio
async def test_queue_pending_decide_consume_roundtrip() -> None:
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
    assert queued.created is True
    listed = await store.list_approvals(status="pending")
    assert len(listed) == 1
    assert listed[0]["approval_request_id"] == queued.approval_request_id
    assert "approval_token" not in listed[0]

    # Pending placeholder token is not consumable.
    pending_fail = store.consume(
        "not-a-real-token",
        actor=actor,
        operation="vm.delete",
        target=target,
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
    )
    assert pending_fail.valid is False

    decided = await store.decide(
        queued.approval_request_id,
        decision="approved",
        decided_by="admin",
        reason="ok",
    )
    assert decided is not None
    assert decided.approval_token is not None
    assert decided.approval["status"] == "approved"

    ok = store.consume(
        decided.approval_token,
        actor=actor,
        operation="vm.delete",
        target=target,
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
    )
    assert ok.valid is True
    again = store.consume(
        decided.approval_token,
        actor=actor,
        operation="vm.delete",
        target=target,
        input_payload={"force": True},
        risk_level="critical",
        risk_score=95,
    )
    assert again.valid is False


@pytest.mark.asyncio
async def test_queue_pending_is_idempotent() -> None:
    store = InMemoryApprovalStore()
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id=None)
    target = Target(resource_type="vm", resource_id="100")
    first = await store.queue_pending(
        operation="vm.delete",
        target=target,
        input_payload={},
        actor=actor,
        risk_level="high",
        risk_score=80,
    )
    second = await store.queue_pending(
        operation="vm.delete",
        target=target,
        input_payload={},
        actor=actor,
        risk_level="high",
        risk_score=80,
    )
    assert first.approval_request_id == second.approval_request_id
    assert second.created is False


def test_operator_cannot_decide_or_put_policy(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, approvals, _store = _client(tmp_path, monkeypatch, role="operator")
    csrf = "csrf_test"

    async def _seed() -> str:
        queued = await approvals.queue_pending(
            operation="vm.delete",
            target=Target(resource_type="vm", resource_id="1"),
            input_payload={},
            actor=ActorIdentity(user_id="u", agent_id="a", tenant_id=None),
            risk_level="high",
            risk_score=80,
        )
        return queued.approval_request_id

    import asyncio

    approval_id = asyncio.run(_seed())
    denied = client.post(
        f"/admin/api/approvals/{approval_id}/decide",
        json={"decision": "approved", "password": "secret123"},
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 403

    policy = client.put(
        "/admin/api/policy",
        json={"dangerous_operations_enabled": False, "password": "secret123"},
        headers={"X-CSRF-Token": csrf},
    )
    assert policy.status_code == 403

    config = client.put(
        "/admin/api/config",
        json={"dangerous_operations_enabled": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert config.status_code == 403


def test_admin_decide_requires_step_up_and_returns_token(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, approvals, _store = _client(tmp_path, monkeypatch, role="admin")
    csrf = "csrf_test"
    import asyncio

    approval_id = asyncio.run(
        approvals.queue_pending(
            operation="vm.delete",
            target=Target(resource_type="vm", resource_id="1"),
            input_payload={},
            actor=ActorIdentity(user_id="u", agent_id="a", tenant_id=None),
            risk_level="high",
            risk_score=80,
        )
    ).approval_request_id

    bad = client.post(
        f"/admin/api/approvals/{approval_id}/decide",
        json={"decision": "approved", "password": "wrong"},
        headers={"X-CSRF-Token": csrf},
    )
    assert bad.status_code == 403

    no_csrf = client.post(
        f"/admin/api/approvals/{approval_id}/decide",
        json={"decision": "approved", "password": "secret123"},
    )
    assert no_csrf.status_code == 403

    ok = client.post(
        f"/admin/api/approvals/{approval_id}/decide",
        json={"decision": "approved", "password": "secret123", "reason": "ship it"},
        headers={"X-CSRF-Token": csrf},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["approval"]["status"] == "approved"
    assert isinstance(body.get("approval_token"), str)
    listed = client.get("/admin/api/approvals").json()["approvals"]
    assert all("approval_token" not in row for row in listed)


def test_restart_requires_step_up(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    exit_calls: list[int] = []
    client, _approvals, store = _client(tmp_path, monkeypatch, role="admin", exit_calls=exit_calls)
    csrf = "csrf_test"
    store.require_restart("secrets changed")

    missing = client.post(
        "/admin/api/runtime/restart",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert missing.status_code == 422

    bad = client.post(
        "/admin/api/runtime/restart",
        json={"password": "wrong"},
        headers={"X-CSRF-Token": csrf},
    )
    assert bad.status_code == 403
    assert exit_calls == []
    assert store.restart_required is True

    ok = client.post(
        "/admin/api/runtime/restart",
        json={"password": "secret123"},
        headers={"X-CSRF-Token": csrf},
    )
    assert ok.status_code == 200
    import time

    time.sleep(1.0)
    assert exit_calls == [0]
    assert store.restart_required is True


def test_policy_updates_live_settings(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _approvals, store = _client(tmp_path, monkeypatch, role="admin")
    csrf = "csrf_test"
    before = store.settings.dangerous_operations.require_approval
    resp = client.put(
        "/admin/api/policy",
        json={
            "dangerous_operations_require_approval": not before,
            "password": "secret123",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    assert store.settings.dangerous_operations.require_approval is (not before)


def test_config_rejects_dangerous_ops_without_policy_path(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _approvals, store = _client(tmp_path, monkeypatch, role="admin")
    csrf = "csrf_test"
    before = store.settings.dangerous_operations.require_approval
    denied = client.put(
        "/admin/api/config",
        json={"dangerous_operations_require_approval": not before},
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 403
    assert store.settings.dangerous_operations.require_approval is before
    assert "policy" in denied.json()["detail"].lower()


def test_step_up_password_is_rate_limited(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from proxmox_mcp.security.rate_limit import FAILED_ADMIN_STEP_UP_LIMITER

    async def _noop_sleep(_seconds: float = 0) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _noop_sleep)
    client, approvals, _store = _client(tmp_path, monkeypatch, role="admin")
    csrf = "csrf_test"
    FAILED_ADMIN_STEP_UP_LIMITER.reset("adminsess_test:testclient")

    approval_id = asyncio.run(
        approvals.queue_pending(
            operation="vm.delete",
            target=Target(resource_type="vm", resource_id="1"),
            input_payload={},
            actor=ActorIdentity(user_id="u", agent_id="a", tenant_id=None),
            risk_level="high",
            risk_score=80,
        )
    ).approval_request_id

    for _ in range(5):
        bad = client.post(
            f"/admin/api/approvals/{approval_id}/decide",
            json={"decision": "approved", "password": "wrong"},
            headers={"X-CSRF-Token": csrf},
        )
        assert bad.status_code == 403

    limited = client.post(
        f"/admin/api/approvals/{approval_id}/decide",
        json={"decision": "approved", "password": "wrong"},
        headers={"X-CSRF-Token": csrf},
    )
    assert limited.status_code == 429
    # Even the correct password is blocked until the window clears.
    blocked = client.post(
        f"/admin/api/approvals/{approval_id}/decide",
        json={"decision": "approved", "password": "secret123"},
        headers={"X-CSRF-Token": csrf},
    )
    assert blocked.status_code == 429
    FAILED_ADMIN_STEP_UP_LIMITER.reset("adminsess_test:testclient")
