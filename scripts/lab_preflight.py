from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Protocol, cast

from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig


class LabPreflightClient(Protocol):
    async def get(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
    ) -> object: ...


async def run_lab_preflight(
    config: LabEnvironmentConfig,
    client: LabPreflightClient,
) -> dict[str, object]:
    if not config.enabled:
        return {"status": "skipped", "reason": config.skip_reason or "lab disabled"}
    missing = config.profile_missing_prerequisites()
    if missing:
        return {"status": "skipped", "reason": "; ".join(missing), "profile": config.profile}
    version_payload = await client.get("/version")
    nodes_payload = await client.get("/nodes")
    storage_payload = await client.get(f"/nodes/{config.node}/storage")

    version = _string_field(version_payload, "version")
    node_names = _field_values(nodes_payload, "node")
    storage_ids = _field_values(storage_payload, "storage")
    expected_storage_ids = config.expected_storage_ids or (
        () if config.storage_id is None else (config.storage_id,)
    )
    missing_storage_ids = [
        storage_id for storage_id in expected_storage_ids if storage_id not in storage_ids
    ]
    checks = {
        "node_present": config.node in node_names,
        "storage_present": config.storage_id is None or config.storage_id in storage_ids,
        "expected_storage_present": not missing_storage_ids,
    }
    status = "passed" if all(checks.values()) else "failed"
    evidence: dict[str, object] = {
        "status": status,
        "endpoint": config.api_endpoint,
        "node": config.node,
        "profile": config.profile,
        "proxmox_version": version,
        "storage_ids": storage_ids,
        "tls_verify": config.tls_verify,
        "auth_method": "api_token" if config.auth_mode == "api_token" else "ticket",
        "checks": checks,
    }
    if missing_storage_ids:
        evidence["missing_storage_ids"] = missing_storage_ids
    return evidence


def build_lab_client(config: LabEnvironmentConfig) -> ProxmoxHttpApiClient:
    if config.api_endpoint is None:
        raise ValueError("Lab API endpoint is not configured")
    if config.auth_mode == "api_token":
        return ProxmoxHttpApiClient(
            api_endpoint=config.api_endpoint,
            token_id=config.token_id,
            token_secret=config.token_secret,
            tls_verify=config.tls_verify,
        )
    return ProxmoxHttpApiClient(
        api_endpoint=config.api_endpoint,
        username=config.username,
        password=config.password,
        tls_verify=config.tls_verify,
    )


async def _main_async(output_file: Path | None) -> int:
    config = LabEnvironmentConfig.from_env(os.environ)
    if not config.enabled:
        print(config.skip_reason or "Lab is not enabled")
        return 0
    evidence = await run_lab_preflight(config, build_lab_client(config))
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if output_file is not None:
        await asyncio.to_thread(_write_text, output_file, rendered)
    print(rendered, end="")
    return 0 if evidence["status"] in {"passed", "skipped"} else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run sanitized Proxmox lab preflight checks.")
    parser.add_argument("--output-file", type=Path)
    args = parser.parse_args(argv)
    return asyncio.run(_main_async(args.output_file))


def _field_values(payload: object, field: str) -> list[str]:
    if not isinstance(payload, list):
        return []
    values: list[str] = []
    for item in cast(list[object], payload):
        if not isinstance(item, dict):
            continue
        value = cast(dict[str, object], item).get(field)
        if isinstance(value, str):
            values.append(value)
    return sorted(values)


def _string_field(payload: object, field: str) -> str:
    if not isinstance(payload, dict):
        return "unknown"
    value = cast(dict[str, object], payload).get(field)
    return value if isinstance(value, str) and value else "unknown"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
