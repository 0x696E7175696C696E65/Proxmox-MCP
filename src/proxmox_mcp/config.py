from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Literal, Self, cast
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from proxmox_mcp.secrets import CredentialPurpose, SecretProviderName


class DangerousOperationSettings(BaseModel):
    enabled: bool = True
    require_approval: bool = True
    log_full_command: bool = False
    require_impact_analysis: bool = True
    require_dry_run_when_supported: bool = True
    require_target_revalidation: bool = True


def _default_generated_cert_dir() -> str:
    return str(Path(tempfile.gettempdir()) / "proxmox-mcp" / "certs")


class TlsSettings(BaseModel):
    """HTTPS server TLS: generate local material or bring-your-own-cert (BYOC).

    - mode=generate: create a local cert (self-signed, or leaf signed by operator CA)
    - mode=byoc: use operator-provided cert_file + key_file (+ optional ca_file)
    """

    mode: Literal["generate", "byoc"] | None = None
    cert_file: str | None = Field(default=None, min_length=1)
    key_file: SecretStr | None = None
    ca_file: str | None = Field(default=None, min_length=1)
    ca_key_file: SecretStr | None = None
    generate_self_signed: bool = True
    generated_cert_dir: str = Field(default_factory=_default_generated_cert_dir, min_length=1)
    common_name: str = Field(default="localhost", min_length=1)
    subject_alt_names: tuple[str, ...] = ("localhost", "127.0.0.1")
    validity_days: int = Field(default=365, ge=1, le=825)
    key_size: int = Field(default=2048, ge=2048, le=4096)

    @field_validator("subject_alt_names", mode="before")
    @classmethod
    def _parse_subject_alt_names(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value

    @model_validator(mode="after")
    def _validate_tls_mode_consistency(self) -> Self:
        if self.mode == "byoc" and (self.cert_file is None or self.key_file is None):
            raise ValueError("TLS mode=byoc requires cert_file and key_file")
        if self.ca_key_file is not None and self.ca_file is None:
            raise ValueError("TLS ca_key_file requires ca_file (operator CA certificate)")
        return self


class ObservabilitySettings(BaseModel):
    alertmanager_url: str | None = None
    alertmanager_required: bool = False
    prometheus_url: str | None = None
    prometheus_required: bool = False
    siem_required: bool = False
    siem_url: str | None = None
    # Homelab Prometheus/Alertmanager on RFC1918 require explicit opt-in.
    allow_private_hosts: bool = False

    @field_validator("alertmanager_url", "prometheus_url", "siem_url")
    @classmethod
    def _require_https_observability_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise ValueError("External observability URLs must use https://")
        return value.rstrip("/")


class DefaultActorSettings(BaseModel):
    user_id: str = Field(default="operator", min_length=1)
    agent_id: str = Field(default="homelab-agent", min_length=1)
    tenant_id: str | None = None


class ServiceTokenActorBinding(BaseModel):
    """Secondary service token → distinct actor + least-privilege role."""

    token_sha256: str = Field(min_length=64, max_length=64)
    user_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    tenant_id: str | None = None
    role: Literal["read_only", "operator", "cluster_admin", "administrator"] = "read_only"


class ClusterCredentialRefSettings(BaseModel):
    provider: SecretProviderName = "development"
    path: str = Field(min_length=1)
    purpose: CredentialPurpose = "proxmox_api"


class ClusterSettings(BaseModel):
    cluster_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    api_endpoint: str = Field(min_length=1)
    tls_verify: bool = True
    credential_ref: ClusterCredentialRefSettings
    environment: Literal["development", "test", "staging", "homelab", "production"] = "homelab"
    status: Literal["active", "disabled"] = "active"

    @model_validator(mode="after")
    def _validate_transport(self) -> Self:
        if not self.api_endpoint.startswith("https://"):
            raise ValueError("Proxmox clusters require https:// API endpoints")
        if self.environment == "production" and not self.tls_verify:
            raise ValueError("Production Proxmox clusters require TLS verification")
        return self


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PROXMOX_MCP_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    environment: Literal["development", "test", "staging", "homelab", "production"] = "development"
    auth_mode: Literal["development", "service_token", "oidc", "mtls", "workload_identity"] = (
        "development"
    )
    external_auth_enabled: bool = False
    durable_state_enabled: bool = False
    workload_identity_replay_cache: Literal["memory", "redis"] = "memory"
    service_token: SecretStr | None = None
    service_token_sha256: str | None = None
    default_actor: DefaultActorSettings = Field(default_factory=DefaultActorSettings)
    mcp_service_role: Literal["read_only", "operator", "cluster_admin", "administrator"] = (
        "read_only"
    )
    service_token_actors: tuple[ServiceTokenActorBinding, ...] = ()
    # None = auto (True except environment=test). Explicit True/False always wins.
    mutations_require_approval: bool | None = None
    approval_sod_enabled: bool = True
    webhook_allow_private_hosts: bool = False
    webhook_max_skew_seconds: int = Field(default=300, ge=30, le=3600)
    # Homelab Proxmox is usually private; public endpoints require explicit opt-in.
    host_allow_public_endpoints: bool = False
    # Break-glass: allow mcp_service_role=administrator (default reject outside test).
    allow_administrator_mcp_role: bool = False
    # Production: shared bearer maps to one actor — require explicit bindings or opt-in.
    allow_shared_service_token_actor: bool = False
    # Break-glass: shared primary token may use cluster_admin/administrator roles.
    allow_shared_service_token_elevated_role: bool = False
    # Dual-control: require 2 distinct approvers for high-risk (critical always N=2).
    approval_dual_control_high: bool = True
    # Linked identity groups for dual-persona SoD (JSON list of string lists via env).
    approval_sod_linked_identities: tuple[tuple[str, ...], ...] = ()
    # Production: reject TLS mode=generate unless break-glass (prefer BYOC).
    allow_generated_tls: bool = False
    secrets_file: str = "/run/proxmox-mcp/secrets/secrets.json"
    cluster: ClusterSettings | None = None
    server_host: str = "127.0.0.1"
    server_port: int = Field(default=8443, ge=1, le=65535)
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://proxmox_mcp:proxmox_mcp@localhost/proxmox_mcp?ssl=require"
    )
    redis_url: SecretStr = SecretStr("rediss://localhost:6379/0")
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    credential_provider: Literal[
        "development",
        "hashicorp_vault",
        "bitwarden",
        "onepassword",
        "aws_secrets_manager",
        "azure_key_vault",
    ] = "development"
    vault_url: str | None = None
    vault_token: SecretStr | None = None
    bitwarden_access_token: SecretStr | None = None
    onepassword_service_account_token: SecretStr | None = None
    aws_region: str | None = None
    azure_key_vault_url: str | None = None
    dangerous_operations: DangerousOperationSettings = Field(
        default_factory=DangerousOperationSettings
    )
    tls: TlsSettings = Field(default_factory=TlsSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    admin_username: str | None = None
    admin_password: SecretStr | None = None
    admin_spa_dir: str = "web/dist"
    approval_webhook_url: str | None = None
    approval_webhook_secret: SecretStr | None = None
    domain_promotions_verify_backup_live: bool = False
    domain_promotions_expand_storage_lvmthin_live: bool = False

    @field_validator("approval_webhook_url")
    @classmethod
    def _validate_approval_webhook_url(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if urlparse(value).scheme != "https":
            raise ValueError("Approval webhook URL must use https://")
        return value.rstrip("/")

    @field_validator("service_token_actors", mode="before")
    @classmethod
    def _parse_service_token_actors(cls, value: object) -> object:
        if value is None or value == "":
            return ()
        if isinstance(value, str):
            import json

            parsed = json.loads(value)
            return parsed
        return value

    @field_validator("approval_sod_linked_identities", mode="before")
    @classmethod
    def _parse_sod_linked_identities(cls, value: object) -> object:
        if value is None or value == "":
            return ()
        if isinstance(value, str):
            import json

            parsed = json.loads(value)
            return parsed
        return value

    @model_validator(mode="after")
    def _validate_encrypted_network_urls(self) -> Settings:
        from proxmox_mcp.approvals.webhook import validate_approval_webhook_url

        _validate_database_url(self.database_url.get_secret_value())
        _validate_redis_url(self.redis_url.get_secret_value())
        _validate_optional_https_url(self.vault_url, "Vault URL")
        _validate_optional_https_url(self.azure_key_vault_url, "Azure Key Vault URL")
        _validate_service_token_configuration(self)
        if self.approval_webhook_url is not None:
            validate_approval_webhook_url(
                self.approval_webhook_url,
                allow_private_hosts=self.webhook_allow_private_hosts,
            )
        if (
            self.mcp_service_role == "administrator"
            and not self.allow_administrator_mcp_role
            and self.environment != "test"
        ):
            raise ValueError(
                "mcp_service_role=administrator requires "
                "PROXMOX_MCP_ALLOW_ADMINISTRATOR_MCP_ROLE=true (break-glass)"
            )
        if (
            self.environment == "production"
            and self.cluster is not None
            and not self.cluster.tls_verify
        ):
            raise ValueError("Production environment requires Proxmox TLS verification")
        if self.environment == "production" and self.auth_mode == "development":
            raise ValueError("Production environment rejects development auth mode")
        _reject_reserved_agent_ids(self)
        _reject_shared_service_token_in_production(self)
        _reject_shared_token_elevated_role(self)
        _reject_unwired_http_auth_modes(self)
        _reject_generated_tls_in_production(self)
        return self

    def sod_linked_identity_groups(self) -> tuple[frozenset[str], ...]:
        """Normalized SoD equivalence groups (config + default actor/admin username)."""
        groups: list[frozenset[str]] = [
            frozenset(item.strip().lower() for item in group if item and item.strip())
            for group in self.approval_sod_linked_identities
        ]
        auto: set[str] = {
            self.default_actor.user_id.strip().lower(),
            self.default_actor.agent_id.strip().lower(),
        }
        if self.admin_username:
            auto.add(self.admin_username.strip().lower())
        if len(auto) >= 2:
            groups.append(frozenset(auto))
        return tuple(group for group in groups if len(group) >= 2)

    def safe_dump(self) -> dict[str, object]:
        from proxmox_mcp.security.redaction import sanitize_for_security_boundary

        dumped = self.model_dump(mode="json")
        sanitized = sanitize_for_security_boundary(dumped)
        if not isinstance(sanitized, dict):
            return {}
        return cast(dict[str, object], sanitized)


def _validate_database_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "postgresql+asyncpg":
        raise ValueError("Database URL must use postgresql+asyncpg")

    query = parse_qs(parsed.query)
    ssl_values = tuple(value.lower() for value in query.get("ssl", ()))
    sslmode_values = tuple(value.lower() for value in query.get("sslmode", ()))
    if not (
        set(ssl_values) & {"require", "required", "verify-ca", "verify-full", "true", "1"}
        or set(sslmode_values) & {"require", "verify-ca", "verify-full"}
    ):
        raise ValueError("PostgreSQL TLS must be required with ssl=require or sslmode=require")


def _validate_redis_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "rediss":
        raise ValueError("Redis TLS requires a rediss:// URL")


def _validate_optional_https_url(value: str | None, label: str) -> None:
    if value is None:
        return
    if urlparse(value).scheme != "https":
        raise ValueError(f"{label} must use https://")


def _validate_service_token_configuration(settings: Settings) -> None:
    if settings.auth_mode != "service_token":
        return
    if settings.service_token is None and settings.service_token_sha256 is None:
        raise ValueError(
            "Service token auth requires PROXMOX_MCP_SERVICE_TOKEN or "
            "PROXMOX_MCP_SERVICE_TOKEN_SHA256"
        )
    if settings.service_token is not None and settings.service_token_sha256 is not None:
        raise ValueError(
            "Configure only one of PROXMOX_MCP_SERVICE_TOKEN or PROXMOX_MCP_SERVICE_TOKEN_SHA256"
        )


# Reserved for Admin UI invoke identity — must never be claimable via MCP tokens.
RESERVED_MCP_AGENT_IDS = frozenset({"admin-ui", "admin_ui", "adminui"})


def _reject_reserved_agent_ids(settings: Settings) -> None:
    default_agent = settings.default_actor.agent_id.strip().lower()
    if default_agent in RESERVED_MCP_AGENT_IDS:
        raise ValueError(
            f"default_actor.agent_id {settings.default_actor.agent_id!r} is reserved "
            "for Admin UI and cannot be used for MCP service tokens"
        )
    for binding in settings.service_token_actors:
        if binding.agent_id.strip().lower() in RESERVED_MCP_AGENT_IDS:
            raise ValueError(
                f"service_token_actors agent_id {binding.agent_id!r} is reserved "
                "for Admin UI and cannot be bound to an MCP token"
            )


def _reject_shared_service_token_in_production(settings: Settings) -> None:
    if settings.environment != "production":
        return
    if settings.auth_mode != "service_token":
        return
    if settings.service_token_actors:
        return
    if settings.allow_shared_service_token_actor:
        return
    raise ValueError(
        "Production service_token auth requires PROXMOX_MCP_SERVICE_TOKEN_ACTORS "
        "bindings (distinct actors per token) or "
        "PROXMOX_MCP_ALLOW_SHARED_SERVICE_TOKEN_ACTOR=true break-glass"
    )


_SHARED_TOKEN_ELEVATED_ROLES = frozenset({"cluster_admin", "administrator"})


def _reject_shared_token_elevated_role(settings: Settings) -> None:
    """Cap blast radius of the primary shared bearer → default_actor mapping."""
    if settings.environment == "test":
        return
    if settings.auth_mode != "service_token":
        return
    if settings.service_token is None and settings.service_token_sha256 is None:
        return
    if settings.mcp_service_role not in _SHARED_TOKEN_ELEVATED_ROLES:
        return
    if settings.allow_shared_service_token_elevated_role:
        return
    raise ValueError(
        "Shared service token with mcp_service_role="
        f"{settings.mcp_service_role!r} requires "
        "PROXMOX_MCP_ALLOW_SHARED_SERVICE_TOKEN_ELEVATED_ROLE=true break-glass, "
        "lower mcp_service_role (read_only|operator), or bind per-token roles via "
        "PROXMOX_MCP_SERVICE_TOKEN_ACTORS"
    )


def _reject_unwired_http_auth_modes(settings: Settings) -> None:
    """OIDC/mTLS/workload_identity need an external gateway resolver — not HTTP bearer."""
    if settings.auth_mode in {"development", "service_token"}:
        return
    if settings.environment == "test":
        return
    if settings.external_auth_enabled:
        return
    raise ValueError(
        f"auth_mode={settings.auth_mode!r} is not wired for direct HTTP MCP auth. "
        "Set PROXMOX_MCP_EXTERNAL_AUTH_ENABLED=true and supply authenticated_session_resolver "
        "via the deployment gateway, or use auth_mode=service_token"
    )


def _reject_generated_tls_in_production(settings: Settings) -> None:
    """Reject explicit generate mode in production (prefer BYOC mounts).

    Implicit generate_self_signed defaults are caught at readiness / serve time so
    unit tests can still construct Settings(environment='production', ...).
    """
    if settings.environment != "production":
        return
    if settings.allow_generated_tls:
        return
    if settings.tls.mode == "generate":
        raise ValueError(
            "Production requires BYOC TLS (PROXMOX_MCP_TLS__MODE=byoc with cert_file+key_file) "
            "or PROXMOX_MCP_ALLOW_GENERATED_TLS=true break-glass"
        )
