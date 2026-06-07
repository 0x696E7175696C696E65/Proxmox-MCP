from __future__ import annotations

import pytest

from proxmox_mcp.proxmox.lab import LabEnvironmentConfig

pytestmark = pytest.mark.lab


def test_storage_expansion_and_benchmark_require_disposable_profile(
    lab_config: LabEnvironmentConfig,
    lab_destructive_enabled: bool,
) -> None:
    _ = lab_destructive_enabled
    if lab_config.profile != "pve-9-storage-local-local-lvm":
        pytest.skip(
            "Select PROXMOX_MCP_LAB_PROFILE=pve-9-storage-local-local-lvm "
            "for storage promotion gates"
        )

    pytest.skip(
        "Live storage expansion and benchmarks remain unpromoted until a disposable thin-pool "
        "profile, bounded workload, artifact path, and cleanup verification are configured"
    )
