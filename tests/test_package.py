import subprocess
import sys

from proxmox_mcp import __version__


def test_version_is_exposed() -> None:
    assert __version__ == "0.1.0"


def test_module_entrypoint_prints_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "proxmox_mcp", "--version"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "proxmox-mcp 0.1.0"
