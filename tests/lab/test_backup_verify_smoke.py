from __future__ import annotations

import pytest

from proxmox_mcp.proxmox.lab import LabEnvironmentConfig

pytestmark = pytest.mark.lab


def test_pbs_backup_verification_requires_profile_prerequisites(
    lab_config: LabEnvironmentConfig,
) -> None:
    if lab_config.profile != "pve-9-pbs-enabled":
        pytest.skip("Select PROXMOX_MCP_LAB_PROFILE=pve-9-pbs-enabled for PBS verification")

    missing = lab_config.profile_missing_prerequisites()
    if missing:
        pytest.skip("; ".join(missing))

    pytest.skip(
        "Live PBS verification is not promoted until repository visibility, artifact addressing, "
        "and verification command/source semantics are recorded in release evidence"
    )
