from __future__ import annotations

from proxmox_mcp.proxmox.cluster_factory import normalize_proxmox_api_endpoint


def test_normalize_proxmox_api_endpoint_strips_api_suffix() -> None:
    assert (
        normalize_proxmox_api_endpoint("https://pve.example.test:8006/api2/json")
        == "https://pve.example.test:8006"
    )


def test_normalize_proxmox_api_endpoint_preserves_base_endpoint() -> None:
    assert (
        normalize_proxmox_api_endpoint("https://pve.example.test:8006")
        == "https://pve.example.test:8006"
    )
