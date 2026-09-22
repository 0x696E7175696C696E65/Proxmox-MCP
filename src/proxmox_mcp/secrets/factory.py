from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from proxmox_mcp.config import Settings
from proxmox_mcp.secrets import DevelopmentSecretProvider, SecretManager


def load_secrets_file(path: str) -> dict[str, dict[str, object]]:
    secrets_path = Path(path)
    if not secrets_path.is_file():
        return {}

    payload = json.loads(secrets_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Secrets file {path} must contain a JSON object")

    secrets: dict[str, dict[str, object]] = {}
    typed_payload = cast(dict[str, object], payload)
    for key, value in typed_payload.items():
        if not isinstance(value, dict):
            raise ValueError(f"Secret entry {key!r} must be a JSON object")
        secrets[key] = cast(dict[str, object], value)
    return secrets


def build_secret_manager(settings: Settings) -> SecretManager:
    provider = settings.credential_provider
    if provider == "development":
        secrets = load_secrets_file(settings.secrets_file)
        allow_production = settings.environment in {"homelab", "staging", "test"}
        development_provider = DevelopmentSecretProvider(
            secrets,
            environment=settings.environment,
            allow_production=allow_production,
        )
        return SecretManager(providers=(development_provider,))

    if provider in {
        "hashicorp_vault",
        "bitwarden",
        "onepassword",
        "aws_secrets_manager",
        "azure_key_vault",
    }:
        raise ValueError(
            f"Secret provider {provider!r} requires deployment-supplied vendor clients"
        )

    raise ValueError(f"Unsupported credential provider: {provider!r}")


def merge_secret_maps(
    left: Mapping[str, Mapping[str, object]],
    right: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    merged = {path: dict(payload) for path, payload in left.items()}
    for path, payload in right.items():
        merged[path] = dict(payload)
    return merged
