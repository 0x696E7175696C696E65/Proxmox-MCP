from __future__ import annotations

import subprocess
import sys

from proxmox_mcp.proxmox.lab import LabEnvironmentConfig
from scripts.lab_prepare_lxc_template import plan_lxc_template_preparation


async def test_lxc_template_prepare_uses_existing_template() -> None:
    config = _config()

    result = await plan_lxc_template_preparation(
        config,
        discovered_template="local:vztmpl/debian-12-standard.tar.zst",
    )

    assert result == {
        "status": "ready",
        "storage": "local",
        "template": "local:vztmpl/debian-12-standard.tar.zst",
        "bootstrap_required": False,
    }


async def test_lxc_template_prepare_skips_when_missing_and_bootstrap_disabled() -> None:
    config = _config()

    result = await plan_lxc_template_preparation(config, discovered_template=None)

    assert result == {
        "status": "skipped",
        "storage": "local",
        "reason": "No LXC template found and bootstrap is not enabled",
        "bootstrap_required": True,
    }


async def test_lxc_template_prepare_requires_helper_script_opt_in_for_bootstrap() -> None:
    config = _config(
        {
            "PROXMOX_MCP_LAB_LXC_TEMPLATE_BOOTSTRAP_ENABLED": "true",
            "PROXMOX_MCP_LAB_LXC_TEMPLATE_NAME": "debian-12-standard.tar.zst",
        }
    )

    result = await plan_lxc_template_preparation(config, discovered_template=None)

    assert result["status"] == "blocked"
    assert result["reason"] == "Set PROXMOX_MCP_LAB_HELPER_SCRIPTS_ENABLED=true"


async def test_lxc_template_prepare_returns_allowlisted_bootstrap_commands() -> None:
    config = _config(
        {
            "PROXMOX_MCP_LAB_LXC_TEMPLATE_BOOTSTRAP_ENABLED": "true",
            "PROXMOX_MCP_LAB_HELPER_SCRIPTS_ENABLED": "true",
            "PROXMOX_MCP_LAB_LXC_TEMPLATE_NAME": "debian-12-standard.tar.zst",
        }
    )

    result = await plan_lxc_template_preparation(config, discovered_template=None)

    assert result == {
        "status": "bootstrap_required",
        "storage": "local",
        "template_name": "debian-12-standard.tar.zst",
        "bootstrap_required": True,
        "api_action": {
            "method": "POST",
            "path": "/nodes/pve-a/aplinfo",
            "data_keys": ["storage", "template"],
        },
        "allowlisted_commands": [
            "pveam update",
            "pveam download local debian-12-standard.tar.zst",
        ],
    }


def test_lxc_template_prepare_cli_help_runs_when_invoked_by_path() -> None:
    result = subprocess.run(  # noqa: S603 - fixed interpreter/script invocation in test
        [sys.executable, "scripts/lab_prepare_lxc_template.py", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Discover or explicitly prepare" in result.stdout


def _config(extra: dict[str, str] | None = None) -> LabEnvironmentConfig:
    env = {
        "PROXMOX_MCP_LAB_ENABLED": "true",
        "PROXMOX_MCP_LAB_API_ENDPOINT": "https://pve.example.test:8006",
        "PROXMOX_MCP_LAB_USERNAME": "root@pam",
        "PROXMOX_MCP_LAB_PASSWORD": "secret-value",
        "PROXMOX_MCP_LAB_NODE": "pve-a",
        "PROXMOX_MCP_LAB_STORAGE": "local",
        "PROXMOX_MCP_LAB_LXC_TEMPLATE_STORAGE": "local",
    }
    if extra:
        env.update(extra)
    return LabEnvironmentConfig.from_env(env)
