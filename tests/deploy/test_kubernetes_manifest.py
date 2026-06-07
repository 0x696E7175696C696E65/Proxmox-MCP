from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml


def _documents() -> list[dict[str, Any]]:
    manifest = Path("deploy/kubernetes/proxmox-mcp.yaml").read_text(encoding="utf-8")
    return [cast(dict[str, Any], doc) for doc in yaml.safe_load_all(manifest) if doc]


def _deployment() -> dict[str, Any]:
    for document in _documents():
        if document.get("kind") == "Deployment":
            return document
    raise AssertionError("Deployment manifest missing")


def _container() -> dict[str, Any]:
    template = cast(dict[str, Any], _deployment()["spec"])["template"]
    spec = cast(dict[str, Any], template)["spec"]
    containers = cast(list[dict[str, Any]], spec["containers"])
    return containers[0]


def _config_map_data() -> dict[str, str]:
    for document in _documents():
        if (
            document.get("kind") == "ConfigMap"
            and document.get("metadata", {}).get("name") == "proxmox-mcp-config"
        ):
            return cast(dict[str, str], document["data"])
    raise AssertionError("proxmox-mcp ConfigMap missing")


def test_kubernetes_probes_use_https_health_endpoints() -> None:
    container = _container()

    readiness = cast(dict[str, Any], container["readinessProbe"])
    liveness = cast(dict[str, Any], container["livenessProbe"])

    assert "tcpSocket" not in readiness
    assert "tcpSocket" not in liveness
    assert readiness["httpGet"] == {
        "path": "/health/ready",
        "port": "https",
        "scheme": "HTTPS",
    }
    assert liveness["httpGet"] == {
        "path": "/health/live",
        "port": "https",
        "scheme": "HTTPS",
    }


def test_kubernetes_manifest_defines_https_startup_probe() -> None:
    startup = cast(dict[str, Any], _container()["startupProbe"])

    assert startup["httpGet"] == {
        "path": "/health/ready",
        "port": "https",
        "scheme": "HTTPS",
    }
    assert startup["failureThreshold"] >= 12


def test_kubernetes_manifest_requires_production_auth_and_tls_config() -> None:
    config = _config_map_data()
    container = _container()
    volume_mounts = {
        cast(str, mount["name"]): mount
        for mount in cast(list[dict[str, Any]], container["volumeMounts"])
    }

    assert config["PROXMOX_MCP_ENVIRONMENT"] == "production"
    assert config["PROXMOX_MCP_AUTH_MODE"] in {"oidc", "mtls", "workload_identity"}
    assert config["PROXMOX_MCP_EXTERNAL_AUTH_ENABLED"] == "true"
    assert config["PROXMOX_MCP_DURABLE_STATE_ENABLED"] == "true"
    assert config["PROXMOX_MCP_WORKLOAD_IDENTITY_REPLAY_CACHE"] == "redis"
    assert config["PROXMOX_MCP_TLS__GENERATE_SELF_SIGNED"] == "false"
    assert volume_mounts["tls"]["readOnly"] is True
