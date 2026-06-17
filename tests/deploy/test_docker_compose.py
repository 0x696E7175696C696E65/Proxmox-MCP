from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml


def _compose(path: str = "docker-compose.yml") -> dict[str, Any]:
    return cast(
        dict[str, Any],
        yaml.safe_load(Path(path).read_text(encoding="utf-8")),
    )


def _merged_homelab_compose() -> dict[str, Any]:
    base = _compose("docker-compose.yml")
    overlay = _compose("docker-compose.homelab.yml")
    services = cast(dict[str, Any], base["services"])
    overlay_services = cast(dict[str, Any], overlay["services"])
    app = cast(dict[str, Any], services["proxmox-mcp"])
    overlay_app = cast(dict[str, Any], overlay_services["proxmox-mcp"])
    app_environment = cast(dict[str, str], app["environment"])
    overlay_environment = cast(dict[str, str], overlay_app["environment"])
    app_environment.update(overlay_environment)
    app_volumes = cast(list[str], app.get("volumes", []))
    app_volumes.extend(cast(list[str], overlay_app.get("volumes", [])))
    app["volumes"] = app_volumes
    app["command"] = overlay_app["command"]
    return base


def test_docker_compose_uses_encrypted_dependency_urls() -> None:
    services = cast(dict[str, Any], _compose()["services"])
    app = cast(dict[str, Any], services["proxmox-mcp"])
    environment = cast(dict[str, str], app["environment"])
    redis_command = cast(list[str], cast(dict[str, Any], services["redis"])["command"])
    postgres_command = cast(list[str], cast(dict[str, Any], services["postgres"])["command"])

    assert "ssl=require" in environment["PROXMOX_MCP_DATABASE_URL"]
    assert environment["PROXMOX_MCP_REDIS_URL"].startswith("rediss://")
    assert "ssl=on" in postgres_command
    assert "--tls-port" in redis_command


def test_dockerfile_declares_https_healthcheck() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert "HEALTHCHECK" in dockerfile
    assert "/health/live" in dockerfile


def test_homelab_compose_overlay_configures_service_token_runtime() -> None:
    compose = _merged_homelab_compose()
    app = cast(dict[str, Any], cast(dict[str, Any], compose["services"])["proxmox-mcp"])
    environment = cast(dict[str, str], app["environment"])
    volumes = cast(list[str], app["volumes"])

    assert environment["PROXMOX_MCP_AUTH_MODE"] == "service_token"
    assert environment["PROXMOX_MCP_DURABLE_STATE_ENABLED"] == "true"
    assert environment["PROXMOX_MCP_CREDENTIAL_PROVIDER"] == "development"
    assert app["command"] == ["proxmox-mcp", "serve", "--mode", "homelab"]
    assert "./secrets.local.json:/run/proxmox-mcp/secrets/secrets.json:ro" in volumes
    assert app["read_only"] is True
    assert app["security_opt"] == ["no-new-privileges:true"]


def test_docker_compose_does_not_expose_credential_defaults() -> None:
    services = cast(dict[str, Any], _compose()["services"])
    app = cast(dict[str, Any], services["proxmox-mcp"])
    postgres = cast(dict[str, Any], services["postgres"])
    app_environment = cast(dict[str, str], app["environment"])
    postgres_environment = cast(dict[str, str], postgres["environment"])

    assert app_environment["PROXMOX_MCP_DATABASE_URL"].startswith("${")
    assert postgres_environment["POSTGRES_PASSWORD"].startswith("${")
