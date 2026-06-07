from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    cert_file: str | None = Field(default=None, min_length=1)
    key_file: SecretStr | None = None
    ca_file: str | None = Field(default=None, min_length=1)
    generate_self_signed: bool = True
    generated_cert_dir: str = Field(default_factory=_default_generated_cert_dir, min_length=1)
    common_name: str = Field(default="localhost", min_length=1)
    subject_alt_names: tuple[str, ...] = ("localhost", "127.0.0.1")

    @field_validator("subject_alt_names", mode="before")
    @classmethod
    def _parse_subject_alt_names(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value


class ObservabilitySettings(BaseModel):
    alertmanager_url: str | None = None
    alertmanager_required: bool = False
    prometheus_url: str | None = None
    prometheus_required: bool = False
    siem_required: bool = False

    @field_validator("alertmanager_url", "prometheus_url")
    @classmethod
    def _require_https_observability_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise ValueError("External observability URLs must use https://")
        return value.rstrip("/")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PROXMOX_MCP_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    environment: Literal["development", "test", "staging", "production"] = "development"
    auth_mode: Literal["development", "service_token", "oidc", "mtls", "workload_identity"] = (
        "development"
    )
    external_auth_enabled: bool = False
    durable_state_enabled: bool = False
    workload_identity_replay_cache: Literal["memory", "redis"] = "memory"
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

    @model_validator(mode="after")
    def _validate_encrypted_network_urls(self) -> Settings:
        _validate_database_url(self.database_url.get_secret_value())
        _validate_redis_url(self.redis_url.get_secret_value())
        _validate_optional_https_url(self.vault_url, "Vault URL")
        _validate_optional_https_url(self.azure_key_vault_url, "Azure Key Vault URL")
        return self

    def safe_dump(self) -> dict[str, object]:
        return self.model_dump(mode="json")


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
