from __future__ import annotations

from pathlib import Path


def test_dockerfile_copies_packaging_metadata_files() -> None:
    dockerfile = Path("Dockerfile").read_text()

    assert "COPY pyproject.toml README.md LICENSE alembic.ini /app/" in dockerfile
    assert "FROM node:22-alpine AS webbuild" in dockerfile
    assert "COPY --from=webbuild /web/dist /app/web/dist" in dockerfile
    assert "PROXMOX_MCP_ADMIN_SPA_DIR=/app/web/dist" in dockerfile


def test_dockerfile_applies_base_security_updates_before_install() -> None:
    dockerfile = Path("Dockerfile").read_text()

    assert "apt-get update" in dockerfile
    assert "apt-get upgrade -y" in dockerfile
    assert 'python -m pip install --upgrade pip "setuptools>=83.0.0" wheel' in dockerfile
    assert '"msgpack>=1.2.1"' in dockerfile
    assert "ensurepip" in dockerfile
    assert "FROM python:3.13-slim AS build" in dockerfile
    assert "FROM python:3.13-slim AS runtime" in dockerfile
    assert "COPY --from=build /usr/local /usr/local" in dockerfile
