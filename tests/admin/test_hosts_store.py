from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from proxmox_mcp.admin.config_store import AdminConfigUpdate, ApplyResult
from proxmox_mcp.admin.hosts_store import (
    HostCatalogError,
    HostCatalogStore,
    HostRecord,
)
from proxmox_mcp.config import ClusterCredentialRefSettings, ClusterSettings, Settings


def _settings(tmp_path: Path, *, secrets: dict[str, dict[str, object]] | None = None) -> Settings:
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(json.dumps(secrets or {}), encoding="utf-8")
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


def _store(
    tmp_path: Path,
    settings: Settings,
    *,
    secrets: dict[str, dict[str, object]] | None = None,
    config_applier=None,
) -> HostCatalogStore:
    hosts_path = tmp_path / "hosts.local.json"

    def load_secrets() -> dict[str, dict[str, object]]:
        path = Path(settings.secrets_file)
        if not path.is_file():
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
        if secrets is not None:
            return secrets
        if isinstance(payload, dict):
            return {str(k): dict(v) for k, v in payload.items() if isinstance(v, dict)}
        return {}

    if config_applier is None:
        config_applier = lambda update: ApplyResult(  # noqa: E731
            kind="hot", changed_fields=tuple(update.model_dump(exclude_none=True)), message="ok"
        )

    return HostCatalogStore(
        path=hosts_path,
        settings=settings,
        secrets_loader=load_secrets,
        config_applier=config_applier,
    )


def test_seed_creates_entry_from_singular_cluster(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(tmp_path, settings)
    state = store.seed_from_settings_if_empty()
    assert len(state.hosts) == 1
    assert state.hosts[0].host_id == "homelab"
    assert state.hosts[0].name == "Homelab Proxmox"
    assert state.hosts[0].api_endpoint == "https://192.168.10.137:8006"
    assert state.hosts[0].credential_ref_path == "clusters/homelab/proxmox-api"
    assert state.active_host_id == "homelab"
    hosts_path = tmp_path / "hosts.local.json"
    on_disk = json.loads(hosts_path.read_text(encoding="utf-8"))
    assert on_disk["active_host_id"] == "homelab"
    assert on_disk["hosts"][0]["host_id"] == "homelab"


def test_seed_is_noop_when_catalog_nonempty(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(tmp_path, settings)
    store.seed_from_settings_if_empty()
    store.upsert(
        HostRecord(
            host_id="pve-b",
            name="PVE B",
            api_endpoint="https://192.168.10.200:8006",
            tls_verify=True,
            credential_ref_path="clusters/pve-b/proxmox-api",
        )
    )
    state = store.seed_from_settings_if_empty()
    assert len(state.hosts) == 2


def test_activate_requires_secrets(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(tmp_path, settings, secrets={})
    store.seed_from_settings_if_empty()
    store.upsert(
        HostRecord(
            host_id="pve-b",
            name="PVE B",
            api_endpoint="https://192.168.10.200:8006",
            tls_verify=True,
            credential_ref_path="clusters/pve-b/proxmox-api",
        )
    )
    with pytest.raises(HostCatalogError, match="(?i)secrets"):
        store.activate("pve-b")


def test_activate_rewrites_cluster_env_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    monkeypatch.setenv("PROXMOX_MCP_ENV_FILE", str(env_file))

    secrets = {
        "clusters/pve-b/proxmox-api": {
            "auth_type": "api_token",
            "token_id": "root@pam!mcp",
            "token_secret": "secret-value",
        }
    }
    settings = _settings(tmp_path, secrets=secrets)
    applied: dict[str, object] = {}

    def fake_apply(update: AdminConfigUpdate) -> ApplyResult:
        applied.update(update.model_dump(exclude_none=True))
        return ApplyResult(kind="hot", changed_fields=tuple(applied), message="ok")

    store = _store(tmp_path, settings, secrets=secrets, config_applier=fake_apply)
    store.seed_from_settings_if_empty()
    store.upsert(
        HostRecord(
            host_id="pve-b",
            name="PVE B",
            api_endpoint="https://192.168.10.200:8006",
            tls_verify=True,
            credential_ref_path="clusters/pve-b/proxmox-api",
        )
    )

    plan = store.activate("pve-b")
    assert plan.host_id == "pve-b"
    assert applied["cluster_api_endpoint"] == "https://192.168.10.200:8006"
    assert applied["cluster_id"] == "pve-b"
    assert applied["credential_ref_path"] == "clusters/pve-b/proxmox-api"
    assert applied["cluster_name"] == "PVE B"
    assert applied["cluster_tls_verify"] is True
    assert store.load().active_host_id == "pve-b"
    assert "PROXMOX_MCP_ACTIVE_HOST_ID=pve-b" in env_file.read_text(encoding="utf-8")
    assert os.environ.get("PROXMOX_MCP_ACTIVE_HOST_ID") == "pve-b"


def test_secrets_ready(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        secrets={
            "clusters/homelab/proxmox-api": {
                "token_id": "id",
                "token_secret": "sec",
            }
        },
    )
    store = _store(tmp_path, settings)
    store.seed_from_settings_if_empty()
    assert store.secrets_ready("homelab") is True
    assert store.secrets_ready("missing") is False


def test_delete_active_raises(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(tmp_path, settings)
    store.seed_from_settings_if_empty()
    store.upsert(
        HostRecord(
            host_id="pve-b",
            name="PVE B",
            api_endpoint="https://192.168.10.200:8006",
            tls_verify=True,
            credential_ref_path="clusters/pve-b/proxmox-api",
        )
    )
    with pytest.raises(HostCatalogError, match="active"):
        store.delete("homelab")


def test_delete_last_host_raises(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(tmp_path, settings)
    store.seed_from_settings_if_empty()
    with pytest.raises(HostCatalogError, match="last"):
        store.delete("homelab")


def test_delete_non_active_host(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = _store(tmp_path, settings)
    store.seed_from_settings_if_empty()
    store.upsert(
        HostRecord(
            host_id="pve-b",
            name="PVE B",
            api_endpoint="https://192.168.10.200:8006",
            tls_verify=True,
            credential_ref_path="clusters/pve-b/proxmox-api",
        )
    )
    store.delete("pve-b")
    state = store.load()
    assert len(state.hosts) == 1
    assert state.hosts[0].host_id == "homelab"
