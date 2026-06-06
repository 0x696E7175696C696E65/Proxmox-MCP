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
