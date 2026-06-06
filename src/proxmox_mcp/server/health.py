from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from proxmox_mcp.config import Settings
from proxmox_mcp.persistence.database import build_async_engine
from proxmox_mcp.persistence.redis import build_redis_client

DependencyStatus = Literal["ok", "unavailable"]


class DependencyCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    required: bool
    status: DependencyStatus
    detail: str = Field(min_length=1)


class LivenessPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]
    service: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)


class ReadinessPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ready", "not_ready"]
    service: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    dependencies: dict[str, DependencyCheck]


class DependencyChecker(Protocol):
    async def check(self, settings: Settings) -> DependencyCheck: ...


@dataclass(frozen=True, slots=True)
class StaticDependencyChecker:
    name: str
    required: bool
    status: DependencyStatus
    detail: str

    async def check(self, settings: Settings) -> DependencyCheck:
        _ = settings
        return DependencyCheck(
            name=self.name,
            required=self.required,
            status=self.status,
            detail=self.detail,
        )


class DatabaseDependencyChecker:
    async def check(self, settings: Settings) -> DependencyCheck:
        engine = build_async_engine(settings)
        try:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        except Exception as exc:  # pragma: no cover - exact driver errors vary
            return DependencyCheck(
                name="postgresql",
                required=True,
                status="unavailable",
                detail=exc.__class__.__name__,
            )
        finally:
            await engine.dispose()

        return DependencyCheck(
            name="postgresql",
            required=True,
            status="ok",
            detail="query succeeded",
        )


class RedisDependencyChecker:
    async def check(self, settings: Settings) -> DependencyCheck:
        client = build_redis_client(settings)
        try:
            await cast(Any, client).ping()
        except Exception as exc:  # pragma: no cover - exact driver errors vary
            return DependencyCheck(
                name="redis",
                required=True,
                status="unavailable",
                detail=exc.__class__.__name__,
            )
        finally:
            await client.aclose()

        return DependencyCheck(name="redis", required=True, status="ok", detail="ping succeeded")


class SecretBackendDependencyChecker:
    async def check(self, settings: Settings) -> DependencyCheck:
        if settings.credential_provider == "development":
            return DependencyCheck(
                name="secret_backend",
                required=True,
                status="ok",
                detail="development provider configured",
            )

        if settings.vault_url and settings.vault_token is not None:
            return DependencyCheck(
                name="secret_backend",
                required=True,
                status="ok",
                detail="hashicorp_vault provider configured",
            )

        return DependencyCheck(
            name="secret_backend",
            required=True,
            status="unavailable",
            detail="hashicorp_vault requires vault_url and vault_token",
        )


class TlsDependencyChecker:
    async def check(self, settings: Settings) -> DependencyCheck:
        tls = settings.tls
        if tls.generate_self_signed:
            return DependencyCheck(
                name="tls",
                required=True,
                status="ok",
                detail="self-signed certificate generation enabled",
            )

        if tls.cert_file is not None and tls.key_file is not None:
            return DependencyCheck(
                name="tls",
                required=True,
                status="ok",
                detail="certificate and key configured",
            )

        return DependencyCheck(
            name="tls",
            required=True,
            status="unavailable",
            detail="certificate and key required when generation is disabled",
        )


class MigrationDependencyChecker:
    async def check(self, settings: Settings) -> DependencyCheck:
        _ = settings
        return DependencyCheck(
            name="migrations",
            required=True,
            status="ok",
            detail="migration gate handled by release qualification workflow",
        )


def build_liveness_payload(settings: Settings) -> LivenessPayload:
    return LivenessPayload(
        status="ok",
        service="enterprise-proxmox-mcp",
        environment=settings.environment,
        port=settings.server_port,
    )


async def build_readiness_payload(
    settings: Settings,
    checkers: Mapping[str, DependencyChecker] | None = None,
) -> ReadinessPayload:
    dependency_checkers = dict(default_dependency_checkers() if checkers is None else checkers)
    dependencies: dict[str, DependencyCheck] = {}
    for name, checker in dependency_checkers.items():
        dependencies[name] = await checker.check(settings)

    is_ready = all(check.status == "ok" for check in dependencies.values() if check.required)
    return ReadinessPayload(
        status="ready" if is_ready else "not_ready",
        service="enterprise-proxmox-mcp",
        environment=settings.environment,
        dependencies=dependencies,
    )


def default_dependency_checkers() -> Mapping[str, DependencyChecker]:
    return {
        "postgresql": DatabaseDependencyChecker(),
        "redis": RedisDependencyChecker(),
        "secret_backend": SecretBackendDependencyChecker(),
        "tls": TlsDependencyChecker(),
        "migrations": MigrationDependencyChecker(),
    }
