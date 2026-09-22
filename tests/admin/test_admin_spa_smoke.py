from pathlib import Path

from starlette.testclient import TestClient

from proxmox_mcp.admin.app import AdminAppState, create_admin_starlette_app
from proxmox_mcp.admin.config_store import ConfigStore, RuntimeController
from proxmox_mcp.admin.events import AdminEventHub
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings


def test_spa_package_manifest_exists() -> None:
    root = Path(__file__).resolve().parents[2]
    assert (root / "web" / "package.json").is_file()
    assert (root / "web" / "index.html").is_file()


def test_spa_dist_built() -> None:
    root = Path(__file__).resolve().parents[2]
    dist = root / "web" / "dist"
    assert (dist / "index.html").is_file(), "Run npm run build in web/"


def test_admin_serves_spa_index(tmp_path, monkeypatch) -> None:
    root = Path(__file__).resolve().parents[2]
    spa_dir = root / "web" / "dist"
    if not (spa_dir / "index.html").is_file():
        return

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
    settings = Settings()
    store = ConfigStore(settings)

    class Repo:
        async def list_events(self, **_kwargs: object) -> list[dict[str, object]]:
            return []

        async def get_event(self, _event_id: str) -> dict[str, object] | None:
            return None

    class Provider:
        async def authenticate(self, *_a: object, **_k: object) -> None:
            return None

        async def create_session(self, *_a: object, **_k: object) -> None:
            raise NotImplementedError

        async def get_session(self, *_a: object, **_k: object) -> None:
            return None

        async def revoke_session(self, *_a: object, **_k: object) -> None:
            return None

        async def ensure_bootstrap_user(self, *_a: object, **_k: object) -> None:
            return None

    state = AdminAppState(
        settings=settings,
        identity_provider=Provider(),  # type: ignore[arg-type]
        config_store=store,
        runtime=RuntimeController(store, exit_fn=lambda _c: None),
        audit_repository=Repo(),  # type: ignore[arg-type]
        audit_writer=InMemoryAuditWriter(),
        event_hub=AdminEventHub(),
        dependency_checkers=None,
        spa_dir=spa_dir,
    )
    client = TestClient(create_admin_starlette_app(state))
    response = client.get("/admin")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
