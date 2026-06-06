from __future__ import annotations

from pathlib import Path


def test_dockerfile_copies_packaging_metadata_files() -> None:
    dockerfile = Path("Dockerfile").read_text()

    assert "COPY pyproject.toml README.md LICENSE /app/" in dockerfile
