from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import text

from proxmox_mcp.config import Settings
from proxmox_mcp.persistence.database import build_async_engine
from proxmox_mcp.persistence.redis import build_redis_client
from proxmox_mcp.proxmox.cluster_factory import (
    cluster_config_from_settings,
    normalize_proxmox_api_endpoint,
)
from proxmox_mcp.server.health import build_readiness_payload, default_dependency_checkers


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    name: str
    detail: str


async def validate_settings_async(settings: Settings) -> list[ValidationIssue]:
    payload = await build_readiness_payload(settings, default_dependency_checkers())
    issues = [
        ValidationIssue(name=name, detail=check.detail)
        for name, check in payload.dependencies.items()
        if check.required and check.status != "ok"
    ]
    if settings.durable_state_enabled and settings.cluster is None:
        issues.append(
            ValidationIssue(
                name="cluster",
                detail="durable homelab runtime requires PROXMOX_MCP_CLUSTER__* configuration",
            )
        )
    return issues


def validate_settings(settings: Settings) -> list[ValidationIssue]:
    return asyncio.run(validate_settings_async(settings))


async def doctor_async(settings: Settings) -> list[ValidationIssue]:
    issues = await validate_settings_async(settings)
    issues.extend(await _probe_postgresql(settings))
    issues.extend(await _probe_redis(settings))
    issues.extend(_probe_proxmox_cluster(settings))
    return issues


def doctor(settings: Settings) -> list[ValidationIssue]:
    return asyncio.run(doctor_async(settings))


async def _probe_postgresql(settings: Settings) -> list[ValidationIssue]:
    engine = build_async_engine(settings)
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except Exception as exc:
        return [ValidationIssue(name="doctor.postgresql", detail=exc.__class__.__name__)]
    finally:
        await engine.dispose()
    return []


async def _probe_redis(settings: Settings) -> list[ValidationIssue]:
    client = build_redis_client(settings)
    try:
        await cast(Any, client).ping()
    except Exception as exc:
        return [ValidationIssue(name="doctor.redis", detail=exc.__class__.__name__)]
    finally:
        await client.aclose()
    return []


def _probe_proxmox_cluster(settings: Settings) -> list[ValidationIssue]:
    cluster = cluster_config_from_settings(settings)
    if cluster is None:
        return []

    endpoint = normalize_proxmox_api_endpoint(cluster.api_endpoint)
    url = f"{endpoint}/api2/json/version"
    request = Request(url, method="GET")  # noqa: S310 - operator-configured HTTPS endpoint.
    try:
        with urlopen(request, timeout=5) as response:  # noqa: S310
            if response.status >= 400:
                return [
                    ValidationIssue(
                        name="doctor.proxmox",
                        detail=f"HTTP {response.status}",
                    )
                ]
    except (HTTPError, URLError, TimeoutError) as exc:
        return [ValidationIssue(name="doctor.proxmox", detail=exc.__class__.__name__)]
    return []
