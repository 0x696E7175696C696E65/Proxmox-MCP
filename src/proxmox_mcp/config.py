from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DangerousOperationSettings(BaseModel):
    enabled: bool = True
    require_approval: bool = True
    log_full_command: bool = False
    require_impact_analysis: bool = True
    require_dry_run_when_supported: bool = True
    require_target_revalidation: bool = True


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PROXMOX_MCP_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    environment: Literal["development", "test", "staging", "production"] = "development"
    server_host: str = "127.0.0.1"
    server_port: int = Field(default=8080, ge=1, le=65535)
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://proxmox_mcp:proxmox_mcp@localhost/proxmox_mcp"
    )
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    credential_provider: Literal["development", "hashicorp_vault"] = "development"
    vault_url: str | None = None
    vault_token: SecretStr | None = None
    dangerous_operations: DangerousOperationSettings = Field(
        default_factory=DangerousOperationSettings
    )

    def safe_dump(self) -> dict[str, object]:
        return self.model_dump(mode="json")
