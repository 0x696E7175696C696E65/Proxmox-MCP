from __future__ import annotations

import pytest

from proxmox_mcp.proxmox.lab import LabEnvironmentConfig

pytestmark = pytest.mark.lab


def test_node_update_orchestration_requires_dedicated_update_profile(
    lab_config: LabEnvironmentConfig,
    lab_destructive_enabled: bool,
) -> None:
    _ = lab_destructive_enabled
    pytest.skip(
        "Node update orchestration remains guarded until a dedicated update lab profile "
        f"records quorum, drain, rollback, reboot, and recovery evidence for {lab_config.profile}"
    )
