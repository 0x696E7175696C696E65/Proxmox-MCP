from __future__ import annotations

from proxmox_mcp.proxmox.lab import LabEnvironmentConfig
from scripts.lab_preflight import LabPreflightClient, run_lab_preflight


class FakePreflightClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def get(self, path: str, *, params: dict[str, object] | None = None) -> object:
        _ = params
        self.calls.append(path)
        if path == "/version":
            return {"version": "9.1.1"}
        if path == "/nodes":
            return [{"node": "pve-a", "status": "online"}]
        if path == "/nodes/pve-a/storage":
            return [{"storage": "local"}, {"storage": "local-lvm"}]
        raise AssertionError(path)


async def test_lab_preflight_returns_sanitized_evidence() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
            "PROXMOX_MCP_LAB_USERNAME": "root@pam",
            "PROXMOX_MCP_LAB_PASSWORD": "secret-value",
            "PROXMOX_MCP_LAB_NODE": "pve-a",
            "PROXMOX_MCP_LAB_STORAGE": "local",
            "PROXMOX_MCP_LAB_EXPECTED_STORAGE_IDS": "local,local-lvm",
            "PROXMOX_MCP_LAB_PROFILE": "pve-9-storage-local-local-lvm",
        }
    )
    client: LabPreflightClient = FakePreflightClient()

    evidence = await run_lab_preflight(config, client)

    assert evidence == {
        "status": "passed",
        "endpoint": "https://pve.example.test:8006",
        "node": "pve-a",
        "profile": "pve-9-storage-local-local-lvm",
        "proxmox_version": "9.1.1",
        "storage_ids": ["local", "local-lvm"],
        "tls_verify": True,
        "auth_method": "ticket",
        "checks": {
            "node_present": True,
            "storage_present": True,
            "expected_storage_present": True,
        },
    }
    assert "password" not in str(evidence).lower()
    assert "root@pam" not in str(evidence)


async def test_lab_preflight_reports_missing_expected_storage_without_secret_data() -> None:
    config = LabEnvironmentConfig.from_env(
        {
            "PROXMOX_MCP_LAB_ENABLED": "true",
            "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
            "PROXMOX_MCP_LAB_USERNAME": "root@pam",
            "PROXMOX_MCP_LAB_PASSWORD": "secret-value",
            "PROXMOX_MCP_LAB_NODE": "pve-a",
            "PROXMOX_MCP_LAB_STORAGE": "missing",
            "PROXMOX_MCP_LAB_EXPECTED_STORAGE_IDS": "local,missing",
        }
    )

    evidence = await run_lab_preflight(config, FakePreflightClient())

    assert evidence["status"] == "failed"
    assert evidence["checks"] == {
        "node_present": True,
        "storage_present": False,
        "expected_storage_present": False,
    }
    assert evidence["missing_storage_ids"] == ["missing"]
