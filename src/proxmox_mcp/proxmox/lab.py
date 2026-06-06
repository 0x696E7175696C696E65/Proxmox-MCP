from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, SecretStr

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


class LabEnvironmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    api_endpoint: str | None = Field(default=None, min_length=1)
    token_id: str | None = Field(default=None, min_length=1)
    token_secret: SecretStr | None = None
    tls_verify: bool = True
    allow_insecure_transport: bool = False
    node: str | None = Field(default=None, min_length=1)
    storage_id: str | None = Field(default=None, min_length=1)
    cluster_id: str = "lab"
    skip_reason: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> LabEnvironmentConfig:
        enabled = _env_bool(env.get("PROXMOX_MCP_LAB_ENABLED"), default=False)
        if not enabled:
            return cls(
                enabled=False,
                skip_reason="Set PROXMOX_MCP_LAB_ENABLED=true to run lab tests",
            )

        missing = [
            name
            for name in (
                "PROXMOX_MCP_LAB_API_ENDPOINT",
                "PROXMOX_MCP_LAB_TOKEN_ID",
                "PROXMOX_MCP_LAB_TOKEN_SECRET",
            )
            if not env.get(name)
        ]
        if missing:
            return cls(
                enabled=False,
                skip_reason="Missing lab environment variables: " + ", ".join(missing),
            )

        endpoint = str(env["PROXMOX_MCP_LAB_API_ENDPOINT"]).rstrip("/")
        parsed_endpoint = urlparse(endpoint)
        if parsed_endpoint.scheme != "https" or parsed_endpoint.username is not None:
            return cls(
                enabled=False,
                skip_reason=("PROXMOX_MCP_LAB_API_ENDPOINT must be an https URL without userinfo"),
            )

        tls_verify = _env_bool(env.get("PROXMOX_MCP_LAB_TLS_VERIFY"), default=True)
        allow_insecure_transport = _env_bool(
            env.get("PROXMOX_MCP_LAB_ALLOW_INSECURE_TRANSPORT"),
            default=False,
        )
        if not tls_verify and not allow_insecure_transport:
            return cls(
                enabled=False,
                skip_reason=(
                    "Set PROXMOX_MCP_LAB_ALLOW_INSECURE_TRANSPORT=true to disable TLS "
                    "verification in disposable labs"
                ),
            )

        return cls(
            enabled=True,
            api_endpoint=endpoint,
            token_id=env["PROXMOX_MCP_LAB_TOKEN_ID"],
            token_secret=SecretStr(env["PROXMOX_MCP_LAB_TOKEN_SECRET"]),
            tls_verify=tls_verify,
            allow_insecure_transport=allow_insecure_transport,
            node=env.get("PROXMOX_MCP_LAB_NODE"),
            storage_id=env.get("PROXMOX_MCP_LAB_STORAGE"),
            cluster_id=env.get("PROXMOX_MCP_LAB_CLUSTER_ID", "lab"),
        )


def _env_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return default
