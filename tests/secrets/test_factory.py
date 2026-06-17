from __future__ import annotations

import json
from pathlib import Path

import pytest

from proxmox_mcp.config import Settings
from proxmox_mcp.secrets.factory import build_secret_manager, load_secrets_file


def test_load_secrets_file_reads_nested_objects(tmp_path: Path) -> None:
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(
        json.dumps(
            {
                "clusters/homelab/proxmox-api": {
                    "auth_type": "api_token",
                    "token_id": "root@pam!mcp",
                    "token_secret": "secret",
                }
            }
        ),
        encoding="utf-8",
    )

    secrets = load_secrets_file(str(secrets_path))

    assert "clusters/homelab/proxmox-api" in secrets
    assert secrets["clusters/homelab/proxmox-api"]["auth_type"] == "api_token"


def test_build_secret_manager_uses_development_provider_from_file(tmp_path: Path) -> None:
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text("{}", encoding="utf-8")
    settings = Settings(
        environment="homelab",
        credential_provider="development",
        secrets_file=str(secrets_path),
    )

    manager = build_secret_manager(settings)

    assert manager is not None


def test_build_secret_manager_rejects_unconfigured_enterprise_provider() -> None:
    settings = Settings(credential_provider="hashicorp_vault")

    with pytest.raises(ValueError, match="vendor clients"):
        build_secret_manager(settings)
