from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from proxmox_mcp.config import Settings

ApplyKind = Literal["hot", "restart"]


class AdminConfigUpdate(BaseModel):
    log_level: Literal["debug", "info", "warning", "error"] | None = None
    cluster_api_endpoint: str | None = None
    cluster_tls_verify: bool | None = None
    cluster_name: str | None = None
    cluster_id: str | None = None
    credential_ref_path: str | None = None
    default_actor_user_id: str | None = None
    default_actor_agent_id: str | None = None
    dangerous_operations_enabled: bool | None = None
    dangerous_operations_require_approval: bool | None = None


class AdminSecretsUpdate(BaseModel):
    proxmox_token_id: str | None = None
    proxmox_token_secret: str | None = None
    service_token: str | None = None


@dataclass(frozen=True, slots=True)
class ApplyResult:
    kind: ApplyKind
    changed_fields: tuple[str, ...]
    message: str


def _mask_secret(value: str | None) -> dict[str, object]:
    if not value:
        return {"configured": False, "last4": None}
    return {"configured": True, "last4": value[-4:] if len(value) >= 4 else value}


def _env_file_path() -> Path:
    return Path(os.environ.get("PROXMOX_MCP_ENV_FILE", ".env"))


def _read_dotenv(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw = stripped.split("=", 1)
        values[key.strip()] = raw.strip()
    return values


def _write_dotenv(path: Path, values: dict[str, str]) -> None:
    existing_lines: list[str] = []
    if path.is_file():
        existing_lines = path.read_text(encoding="utf-8").splitlines()

    written: set[str] = set()
    output: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            output.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in values:
            output.append(f"{key}={values[key]}")
            written.add(key)
        else:
            output.append(line)
    for key, value in values.items():
        if key not in written:
            output.append(f"{key}={value}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(output) + "\n", encoding="utf-8")


class ConfigStore:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._restart_required = False
        self._last_message = "idle"

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def restart_required(self) -> bool:
        return self._restart_required

    @property
    def last_message(self) -> str:
        return self._last_message

    def public_config(self) -> dict[str, Any]:
        cluster = self._settings.cluster
        return {
            "environment": self._settings.environment,
            "auth_mode": self._settings.auth_mode,
            "log_level": self._settings.log_level,
            "server_host": self._settings.server_host,
            "server_port": self._settings.server_port,
            "cluster": None
            if cluster is None
            else {
                "cluster_id": cluster.cluster_id,
                "name": cluster.name,
                "api_endpoint": cluster.api_endpoint,
                "tls_verify": cluster.tls_verify,
                "environment": cluster.environment,
                "credential_path": cluster.credential_ref.path,
            },
            "default_actor": {
                "user_id": self._settings.default_actor.user_id,
                "agent_id": self._settings.default_actor.agent_id,
                "tenant_id": self._settings.default_actor.tenant_id,
            },
            "dangerous_operations": {
                "enabled": self._settings.dangerous_operations.enabled,
                "require_approval": self._settings.dangerous_operations.require_approval,
            },
            "restart_required": self._restart_required,
            "last_message": self._last_message,
            "config_version": self.config_version(),
        }

    def config_version(self) -> str:
        import hashlib
        import json

        payload = {
            "environment": self._settings.environment,
            "auth_mode": self._settings.auth_mode,
            "log_level": self._settings.log_level,
            "dangerous_operations": {
                "enabled": self._settings.dangerous_operations.enabled,
                "require_approval": self._settings.dangerous_operations.require_approval,
            },
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    def secrets_version(self) -> str:
        import hashlib
        import json

        payload = {k: v for k, v in self.public_secrets().items() if k != "config_version"}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    def public_secrets(self) -> dict[str, Any]:
        secrets = self._load_secrets()
        path = (
            self._settings.cluster.credential_ref.path
            if self._settings.cluster is not None
            else "clusters/homelab/proxmox-api"
        )
        entry = secrets.get(path, {})
        token_secret = entry.get("token_secret")
        token_id = entry.get("token_id")
        service = (
            self._settings.service_token.get_secret_value()
            if self._settings.service_token is not None
            else None
        )
        payload = {
            "proxmox_token_id": token_id if isinstance(token_id, str) else None,
            "proxmox_token_secret": _mask_secret(
                token_secret if isinstance(token_secret, str) else None
            ),
            "service_token": _mask_secret(service),
            "credential_path": path,
        }
        import hashlib
        import json

        version = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()
        return {**payload, "config_version": version}

    def reveal_secret(self, name: Literal["proxmox_token_secret", "service_token"]) -> str | None:
        if name == "service_token":
            if self._settings.service_token is None:
                return None
            return self._settings.service_token.get_secret_value()
        secrets = self._load_secrets()
        path = (
            self._settings.cluster.credential_ref.path
            if self._settings.cluster is not None
            else "clusters/homelab/proxmox-api"
        )
        entry = secrets.get(path, {})
        value = entry.get("token_secret")
        return value if isinstance(value, str) else None

    def apply_config(self, update: AdminConfigUpdate) -> ApplyResult:
        changed: list[str] = []
        env_updates: dict[str, str] = {}
        data = update.model_dump(exclude_none=True)

        mapping = {
            "log_level": "PROXMOX_MCP_LOG_LEVEL",
            "cluster_api_endpoint": "PROXMOX_MCP_CLUSTER__API_ENDPOINT",
            "cluster_tls_verify": "PROXMOX_MCP_CLUSTER__TLS_VERIFY",
            "cluster_name": "PROXMOX_MCP_CLUSTER__NAME",
            "cluster_id": "PROXMOX_MCP_CLUSTER__CLUSTER_ID",
            "credential_ref_path": "PROXMOX_MCP_CLUSTER__CREDENTIAL_REF__PATH",
            "default_actor_user_id": "PROXMOX_MCP_DEFAULT_ACTOR__USER_ID",
            "default_actor_agent_id": "PROXMOX_MCP_DEFAULT_ACTOR__AGENT_ID",
            "dangerous_operations_enabled": "PROXMOX_MCP_DANGEROUS_OPERATIONS__ENABLED",
            "dangerous_operations_require_approval": (
                "PROXMOX_MCP_DANGEROUS_OPERATIONS__REQUIRE_APPROVAL"
            ),
        }
        for field_name, env_key in mapping.items():
            if field_name not in data:
                continue
            value = data[field_name]
            env_updates[env_key] = (
                "true" if value is True else "false" if value is False else str(value)
            )
            changed.append(field_name)
            os.environ[env_key] = env_updates[env_key]

        if env_updates:
            _write_dotenv(_env_file_path(), {**_read_dotenv(_env_file_path()), **env_updates})

        # Rebuild settings from environment for hot fields.
        self._settings = Settings()
        self._last_message = f"Applied {len(changed)} config field(s)"
        return ApplyResult(kind="hot", changed_fields=tuple(changed), message=self._last_message)

    def apply_secrets(self, update: AdminSecretsUpdate) -> ApplyResult:
        changed: list[str] = []
        restart = False

        if update.service_token is not None:
            env_path = _env_file_path()
            values = _read_dotenv(env_path)
            values["PROXMOX_MCP_SERVICE_TOKEN"] = update.service_token
            _write_dotenv(env_path, values)
            os.environ["PROXMOX_MCP_SERVICE_TOKEN"] = update.service_token
            changed.append("service_token")
            restart = True

        if update.proxmox_token_id is not None or update.proxmox_token_secret is not None:
            secrets = self._load_secrets()
            path = (
                self._settings.cluster.credential_ref.path
                if self._settings.cluster is not None
                else "clusters/homelab/proxmox-api"
            )
            entry = dict(secrets.get(path, {}))
            entry.setdefault("auth_type", "api_token")
            if update.proxmox_token_id is not None:
                entry["token_id"] = update.proxmox_token_id
                changed.append("proxmox_token_id")
            if update.proxmox_token_secret is not None:
                entry["token_secret"] = update.proxmox_token_secret
                changed.append("proxmox_token_secret")
            secrets[path] = entry
            self._write_secrets(secrets)
            # Proxmox client is process-bound; require restart after credential material change.
            restart = True

        if restart:
            self._restart_required = True
            self._last_message = "Secrets updated; restart required for credential/token changes"
            return ApplyResult(
                kind="restart",
                changed_fields=tuple(changed),
                message=self._last_message,
            )

        self._settings = Settings()
        self._last_message = f"Applied {len(changed)} secret field(s)"
        return ApplyResult(kind="hot", changed_fields=tuple(changed), message=self._last_message)

    def mark_restarted(self) -> None:
        self._restart_required = False
        self._last_message = "Runtime restarted"

    def set_restart_pending_message(self, message: str) -> None:
        self._last_message = message

    def require_restart(self, message: str) -> None:
        self._restart_required = True
        self._last_message = message

    def load_secrets(self) -> dict[str, dict[str, object]]:
        """Load secrets.json as a nested mapping (empty when missing/invalid)."""
        path = Path(self._settings.secrets_file)
        if not path.is_file():
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        result: dict[str, dict[str, object]] = {}
        for key, value in payload.items():
            if isinstance(value, dict):
                result[str(key)] = dict(value)
        return result

    def _load_secrets(self) -> dict[str, dict[str, object]]:
        return self.load_secrets()

    def _write_secrets(self, secrets: dict[str, dict[str, object]]) -> None:
        path = Path(self._settings.secrets_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(secrets, indent=2) + "\n", encoding="utf-8")


class RuntimeController:
    def __init__(
        self,
        config_store: ConfigStore,
        *,
        exit_fn: Any | None = None,
    ) -> None:
        self._config_store = config_store
        self._restart_requested = False
        self._exit_fn = exit_fn if exit_fn is not None else os._exit
        # New process boot: clear any prior restart_required semantics.
        self._config_store.mark_restarted()

    @property
    def status(self) -> dict[str, object]:
        return {
            "restart_required": self._config_store.restart_required,
            "restart_requested": self._restart_requested,
            "message": self._config_store.last_message,
        }

    def request_restart(self, *, delay_seconds: float = 0.75) -> dict[str, object]:
        self._restart_requested = True
        # Keep restart_required until the next process boot clears it via mark_restarted().
        self._config_store.set_restart_pending_message("Restart requested; process exiting")

        # Defer exit so the HTTP response (activate / restart) can flush to the client
        # before Docker's restart policy recycles the process.
        def _exit() -> None:
            self._exit_fn(0)

        if delay_seconds <= 0:
            _exit()
        else:
            import threading

            threading.Timer(delay_seconds, _exit).start()
        return self.status
