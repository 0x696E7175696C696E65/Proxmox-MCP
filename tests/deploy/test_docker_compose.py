from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml


def _compose() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8")),
    )


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


def test_docker_compose_does_not_expose_credential_defaults() -> None:
    services = cast(dict[str, Any], _compose()["services"])
    app = cast(dict[str, Any], services["proxmox-mcp"])
    postgres = cast(dict[str, Any], services["postgres"])
    app_environment = cast(dict[str, str], app["environment"])
    postgres_environment = cast(dict[str, str], postgres["environment"])

    assert app_environment["PROXMOX_MCP_DATABASE_URL"].startswith("${")
    assert postgres_environment["POSTGRES_PASSWORD"].startswith("${")
