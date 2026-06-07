from __future__ import annotations

from pathlib import Path


def test_dockerfile_copies_packaging_metadata_files() -> None:
    dockerfile = Path("Dockerfile").read_text()

    assert "COPY pyproject.toml README.md LICENSE /app/" in dockerfile


def test_dockerfile_applies_base_security_updates_before_install() -> None:
    dockerfile = Path("Dockerfile").read_text()

    assert "apt-get update" in dockerfile
    assert "apt-get upgrade -y" in dockerfile
    assert "python -m pip install --upgrade pip setuptools wheel" in dockerfile
