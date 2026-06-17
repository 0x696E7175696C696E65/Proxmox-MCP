# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import (
    ClusterCredentialRefSettings,
    ClusterSettings,
    Settings,
    TlsSettings,
)
from proxmox_mcp.server.runtime import build_runtime_async


@pytest.fixture
def homelab_settings(tmp_path: Path) -> Settings:
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
    database_path = tmp_path / "runtime.db"
    database_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    return Settings.model_construct(
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
        tls=TlsSettings(generate_self_signed=True),
    )


@pytest.mark.asyncio
async def test_build_runtime_async_wires_durable_components(
    homelab_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_redis_ping() -> bool:
        return True

    monkeypatch.setattr(
        "proxmox_mcp.server.config_validation.build_redis_client",
        lambda settings: type(
            "FakeRedis",
            (),
            {"ping": fake_redis_ping, "aclose": staticmethod(lambda: None)},
        )(),
    )

    bundle = await build_runtime_async(homelab_settings)

    assert bundle.proxmox_client is not None
    assert not isinstance(bundle.audit_writer, InMemoryAuditWriter)
    assert bundle.authenticated_session_resolver is not None
    assert bundle.dependency_checkers["production_state"] is not None


@pytest.mark.asyncio
async def test_build_runtime_requires_durable_state_enabled() -> None:
    settings = Settings(durable_state_enabled=False)

    with pytest.raises(ValueError, match="DURABLE_STATE_ENABLED"):
        await build_runtime_async(settings)
