from __future__ import annotations

from pathlib import Path

import pytest

from proxmox_mcp.admin.config_store import AdminConfigUpdate, ApplyResult, ConfigStore
from proxmox_mcp.admin.hosts_store import HostCatalogState, HostCatalogStore, HostRecord
from proxmox_mcp.config import (
    ClusterCredentialRefSettings,
    ClusterSettings,
    Settings,
)


def _settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, endpoint: str) -> Settings:
    secrets = tmp_path / "secrets.json"
    secrets.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("PROXMOX_MCP_ENV_FILE", str(tmp_path / ".env"))
    monkeypatch.setenv("PROXMOX_MCP_SECRETS_FILE", str(secrets))
    # model_construct: avoid auth validators that need a real service token in unit tests
    return Settings.model_construct(
        environment="homelab",
        auth_mode="service_token",
        secrets_file=str(secrets),
        cluster=ClusterSettings(
            cluster_id="homelab",
            name="Homelab Proxmox",
            api_endpoint=endpoint,
            tls_verify=False,
            credential_ref=ClusterCredentialRefSettings(
                provider="development",
                path="clusters/homelab/proxmox-api",
            ),
            environment="homelab",
        ),
    )


def test_reconcile_applies_catalog_active_over_stale_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(monkeypatch, tmp_path, endpoint="https://192.168.10.137:8006")
    hosts_path = tmp_path / "hosts.local.json"
    store = ConfigStore(settings)
    applied: list[AdminConfigUpdate] = []

    def capture(update: AdminConfigUpdate) -> ApplyResult:
        applied.append(update)
        return store.apply_config(update)

    catalog = HostCatalogStore(
        path=hosts_path,
        settings=settings,
        secrets_loader=lambda: {},
        config_applier=capture,
    )
    hosts = [
        HostRecord(
            host_id="homelab",
            name="Homelab Proxmox",
            api_endpoint="https://192.168.10.137:8006",
            tls_verify=False,
            credential_ref_path="clusters/homelab/proxmox-api",
        ),
        HostRecord(
            host_id="pve-168",
            name="PVE 168",
            api_endpoint="https://192.168.10.168:8006",
            tls_verify=False,
            credential_ref_path="clusters/pve-168/proxmox-api",
        ),
    ]
    catalog._save(HostCatalogState(hosts=hosts, active_host_id="pve-168"))  # noqa: SLF001

    changed = catalog.reconcile_active_into_runtime()
    assert changed is True
    assert applied[-1].cluster_id == "pve-168"
    assert applied[-1].cluster_api_endpoint == "https://192.168.10.168:8006"
    assert applied[-1].cluster_name == "PVE 168"


def test_reconcile_noop_when_already_matching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(monkeypatch, tmp_path, endpoint="https://192.168.10.137:8006")
    hosts_path = tmp_path / "hosts.local.json"
    calls: list[object] = []
    catalog = HostCatalogStore(
        path=hosts_path,
        settings=settings,
        secrets_loader=lambda: {},
        config_applier=lambda u: calls.append(u)
        or ApplyResult(kind="hot", changed_fields=(), message="x"),
    )
    catalog.seed_from_settings_if_empty()
    assert catalog.reconcile_active_into_runtime() is False
    assert calls == []
