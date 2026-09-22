from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clear_proxmox_mcp_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep Settings() tests hermetic on runners that inject host cluster/env vars."""
    for key in list(os.environ):
        if key.startswith("PROXMOX_MCP_"):
            monkeypatch.delenv(key, raising=False)
