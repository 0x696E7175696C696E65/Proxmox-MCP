from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from proxmox_mcp.admin.config_store import (
    AdminConfigUpdate,
    ApplyResult,
    _env_file_path,
    _read_dotenv,
    _write_dotenv,
)
from proxmox_mcp.config import Settings

ACTIVE_HOST_ENV_KEY = "PROXMOX_MCP_ACTIVE_HOST_ID"


class HostCatalogError(Exception):
    pass


class HostRecord(BaseModel):
    host_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    api_endpoint: str = Field(min_length=1)
    tls_verify: bool = True
    credential_ref_path: str = Field(min_length=1)
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class HostCatalogState:
    hosts: list[HostRecord]
    active_host_id: str | None


@dataclass(frozen=True, slots=True)
class ActivatePlan:
    host_id: str
    active_host_id: str
    apply_result: ApplyResult


SecretsLoader = Callable[[], dict[str, dict[str, object]]]
ConfigApplier = Callable[[AdminConfigUpdate], ApplyResult]


class HostCatalogStore:
    def __init__(
        self,
        *,
        path: Path,
        settings: Settings,
        secrets_loader: SecretsLoader,
        config_applier: ConfigApplier,
    ) -> None:
        self._path = path
        self._settings = settings
        self._secrets_loader = secrets_loader
        self._config_applier = config_applier

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> HostCatalogState:
        if not self._path.is_file():
            return HostCatalogState(hosts=[], active_host_id=None)
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return HostCatalogState(hosts=[], active_host_id=None)
        raw_hosts = payload.get("hosts", [])
        hosts: list[HostRecord] = []
        if isinstance(raw_hosts, list):
            for item in raw_hosts:
                if isinstance(item, dict):
                    hosts.append(HostRecord.model_validate(item))
        active = payload.get("active_host_id")
        active_host_id = active if isinstance(active, str) and active else None
        return HostCatalogState(hosts=hosts, active_host_id=active_host_id)

    def seed_from_settings_if_empty(self) -> HostCatalogState:
        state = self.load()
        if state.hosts:
            return state
        cluster = self._settings.cluster
        if cluster is None:
            return state
        record = HostRecord(
            host_id=cluster.cluster_id,
            name=cluster.name,
            api_endpoint=cluster.api_endpoint,
            tls_verify=cluster.tls_verify,
            credential_ref_path=cluster.credential_ref.path,
            enabled=True,
        )
        seeded = HostCatalogState(hosts=[record], active_host_id=record.host_id)
        self._save(seeded)
        return seeded

    def upsert(self, record: HostRecord) -> HostRecord:
        state = self.load()
        hosts = [h for h in state.hosts if h.host_id != record.host_id]
        hosts.append(record)
        self._save(HostCatalogState(hosts=hosts, active_host_id=state.active_host_id))
        return record

    def delete(self, host_id: str) -> None:
        state = self.load()
        if not any(h.host_id == host_id for h in state.hosts):
            raise HostCatalogError(f"Host {host_id!r} not found")
        if len(state.hosts) <= 1:
            raise HostCatalogError("Cannot delete the last remaining host")
        if state.active_host_id == host_id:
            raise HostCatalogError("Cannot delete the active host")
        hosts = [h for h in state.hosts if h.host_id != host_id]
        self._save(HostCatalogState(hosts=hosts, active_host_id=state.active_host_id))

    def secrets_ready(self, host_id: str) -> bool:
        state = self.load()
        record = _find_host(state.hosts, host_id)
        if record is None:
            return False
        return _entry_has_tokens(self.credential_entry(record.credential_ref_path))

    def credential_entry(self, credential_ref_path: str) -> dict[str, object]:
        entry = self._secrets_loader().get(credential_ref_path, {})
        return dict(entry) if isinstance(entry, dict) else {}

    def reconcile_active_into_runtime(self) -> bool:
        """Apply catalog active host into Settings/env when Docker env is stale.

        Docker ``restart`` keeps the container's original env from ``compose up``.
        The catalog file is mounted RW and is the source of truth after a switch.
        Returns True when runtime cluster settings were rewritten.
        """
        state = self.load()
        if not state.active_host_id:
            return False
        record = _find_host(state.hosts, state.active_host_id)
        if record is None or not record.enabled:
            return False
        cluster = self._settings.cluster
        if (
            cluster is not None
            and cluster.cluster_id == record.host_id
            and cluster.api_endpoint == record.api_endpoint
            and cluster.name == record.name
            and cluster.tls_verify == record.tls_verify
            and cluster.credential_ref.path == record.credential_ref_path
        ):
            return False
        self._config_applier(
            AdminConfigUpdate(
                cluster_api_endpoint=record.api_endpoint,
                cluster_tls_verify=record.tls_verify,
                cluster_name=record.name,
                cluster_id=record.host_id,
                credential_ref_path=record.credential_ref_path,
            )
        )
        self._persist_active_host_id(record.host_id)
        self._settings = Settings()
        return True

    def activate(self, host_id: str) -> ActivatePlan:
        state = self.load()
        record = _find_host(state.hosts, host_id)
        if record is None:
            raise HostCatalogError(f"Host {host_id!r} not found")
        if not record.enabled:
            raise HostCatalogError(f"Host {host_id!r} is disabled")
        if not self.secrets_ready(host_id):
            raise HostCatalogError(
                f"Secrets are not ready for host {host_id!r}; "
                "configure token_id and token_secret at the credential path"
            )

        update = AdminConfigUpdate(
            cluster_api_endpoint=record.api_endpoint,
            cluster_tls_verify=record.tls_verify,
            cluster_name=record.name,
            cluster_id=record.host_id,
            credential_ref_path=record.credential_ref_path,
        )
        apply_result = self._config_applier(update)

        updated = HostCatalogState(hosts=state.hosts, active_host_id=host_id)
        self._save(updated)
        self._persist_active_host_id(host_id)
        self._settings = Settings()

        return ActivatePlan(
            host_id=host_id,
            active_host_id=host_id,
            apply_result=apply_result,
        )

    def _persist_active_host_id(self, host_id: str) -> None:
        env_path = _env_file_path()
        values = {**_read_dotenv(env_path), ACTIVE_HOST_ENV_KEY: host_id}
        _write_dotenv(env_path, values)
        os.environ[ACTIVE_HOST_ENV_KEY] = host_id

    def _save(self, state: HostCatalogState) -> None:
        payload: dict[str, Any] = {
            "active_host_id": state.active_host_id,
            "hosts": [h.model_dump() for h in state.hosts],
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _find_host(hosts: list[HostRecord], host_id: str) -> HostRecord | None:
    for host in hosts:
        if host.host_id == host_id:
            return host
    return None


def _entry_has_tokens(entry: dict[str, object]) -> bool:
    token_id = entry.get("token_id")
    token_secret = entry.get("token_secret")
    return (
        isinstance(token_id, str)
        and bool(token_id)
        and isinstance(token_secret, str)
        and bool(token_secret)
    )
