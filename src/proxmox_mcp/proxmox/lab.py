from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, cast
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, SecretStr

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
LabAuthMode = Literal["api_token", "username_password"]
LabProfileName = Literal[
    "pve-9-single-node-no-ceph",
    "pve-9-storage-local-local-lvm",
    "pve-9-single-node-with-guests",
    "pve-9-ceph-enabled",
    "pve-9-ha-enabled",
    "pve-9-multi-node",
    "pve-9-pbs-enabled",
]

LAB_PROFILE_NAMES: frozenset[str] = frozenset(
    {
        "pve-9-single-node-no-ceph",
        "pve-9-storage-local-local-lvm",
        "pve-9-single-node-with-guests",
        "pve-9-ceph-enabled",
        "pve-9-ha-enabled",
        "pve-9-multi-node",
        "pve-9-pbs-enabled",
    }
)


class LabEnvironmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    api_endpoint: str | None = Field(default=None, min_length=1)
    auth_mode: LabAuthMode | None = None
    token_id: str | None = Field(default=None, min_length=1)
    token_secret: SecretStr | None = None
    username: str | None = Field(default=None, min_length=1)
    password: SecretStr | None = None
    tls_verify: bool = True
    allow_insecure_transport: bool = False
    node: str | None = Field(default=None, min_length=1)
    storage_id: str | None = Field(default=None, min_length=1)
    cluster_id: str = "lab"
    profile: LabProfileName = "pve-9-single-node-no-ceph"
    skip_reason: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> LabEnvironmentConfig:
        enabled = _env_bool(env.get("PROXMOX_MCP_LAB_ENABLED"), default=False)
        if not enabled:
            return cls(
                enabled=False,
                skip_reason="Set PROXMOX_MCP_LAB_ENABLED=true to run lab tests",
            )

        missing = [name for name in ("PROXMOX_MCP_LAB_API_ENDPOINT",) if not env.get(name)]
        if missing:
            return cls(
                enabled=False,
                skip_reason="Missing lab environment variables: " + ", ".join(missing),
            )

        has_token_credentials = bool(
            env.get("PROXMOX_MCP_LAB_TOKEN_ID") and env.get("PROXMOX_MCP_LAB_TOKEN_SECRET")
        )
        has_password_credentials = bool(
            env.get("PROXMOX_MCP_LAB_USERNAME") and env.get("PROXMOX_MCP_LAB_PASSWORD")
        )
        if has_token_credentials == has_password_credentials:
            return cls(
                enabled=False,
                skip_reason=(
                    "Configure exactly one token or username/password lab credentials set"
                ),
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

        raw_profile = env.get("PROXMOX_MCP_LAB_PROFILE", "pve-9-single-node-no-ceph")
        if raw_profile not in LAB_PROFILE_NAMES:
            return cls(
                enabled=False,
                skip_reason=f"Unknown Proxmox lab profile: {raw_profile}",
            )

        return cls(
            enabled=True,
            api_endpoint=endpoint,
            auth_mode="api_token" if has_token_credentials else "username_password",
            token_id=env.get("PROXMOX_MCP_LAB_TOKEN_ID"),
            token_secret=None
            if env.get("PROXMOX_MCP_LAB_TOKEN_SECRET") is None
            else SecretStr(env["PROXMOX_MCP_LAB_TOKEN_SECRET"]),
            username=env.get("PROXMOX_MCP_LAB_USERNAME"),
            password=None
            if env.get("PROXMOX_MCP_LAB_PASSWORD") is None
            else SecretStr(env["PROXMOX_MCP_LAB_PASSWORD"]),
            tls_verify=tls_verify,
            allow_insecure_transport=allow_insecure_transport,
            node=env.get("PROXMOX_MCP_LAB_NODE"),
            storage_id=env.get("PROXMOX_MCP_LAB_STORAGE"),
            cluster_id=env.get("PROXMOX_MCP_LAB_CLUSTER_ID", "lab"),
            profile=cast(LabProfileName, raw_profile),
        )

    def profile_missing_prerequisites(self) -> tuple[str, ...]:
        missing: list[str] = []
        if (
            self.profile
            in {
                "pve-9-single-node-no-ceph",
                "pve-9-storage-local-local-lvm",
                "pve-9-single-node-with-guests",
                "pve-9-ceph-enabled",
                "pve-9-ha-enabled",
                "pve-9-multi-node",
                "pve-9-pbs-enabled",
            }
            and self.node is None
        ):
            missing.append("Set PROXMOX_MCP_LAB_NODE for node-scoped storage profile tests")

        if (
            self.profile
            in {
                "pve-9-single-node-no-ceph",
                "pve-9-storage-local-local-lvm",
            }
            and self.storage_id is None
        ):
            missing.append("Set PROXMOX_MCP_LAB_STORAGE for local storage profile tests")

        return tuple(missing)


def _env_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return default
