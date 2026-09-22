from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from proxmox_mcp.proxmox.lab import LabEnvironmentConfig
from proxmox_mcp.proxmox.lab_resources import DisposableProxmoxResources

try:
    from scripts.lab_preflight import build_lab_client
except ModuleNotFoundError:  # pragma: no cover - exercised by path-based CLI invocation
    from lab_preflight import build_lab_client


async def plan_lxc_template_preparation(
    config: LabEnvironmentConfig,
    *,
    discovered_template: str | None,
) -> dict[str, object]:
    storage = config.lxc_template_storage_id or config.storage_id or "local"
    if discovered_template is not None:
        return {
            "status": "ready",
            "storage": storage,
            "template": discovered_template,
            "bootstrap_required": False,
        }
    if not config.lxc_template_bootstrap_enabled:
        return {
            "status": "skipped",
            "storage": storage,
            "reason": "No LXC template found and bootstrap is not enabled",
            "bootstrap_required": True,
        }
    if not config.helper_scripts_enabled:
        return {
            "status": "blocked",
            "storage": storage,
            "reason": "Set PROXMOX_MCP_LAB_HELPER_SCRIPTS_ENABLED=true",
            "bootstrap_required": True,
        }
    if config.lxc_template_name is None:
        return {
            "status": "blocked",
            "storage": storage,
            "reason": "Set PROXMOX_MCP_LAB_LXC_TEMPLATE_NAME",
            "bootstrap_required": True,
        }
    return {
        "status": "bootstrap_required",
        "storage": storage,
        "template_name": config.lxc_template_name,
        "bootstrap_required": True,
        "api_action": {
            "method": "POST",
            "path": f"/nodes/{config.node}/aplinfo",
            "data_keys": ["storage", "template"],
        },
        "allowlisted_commands": [
            "pveam update",
            f"pveam download {storage} {config.lxc_template_name}",
        ],
    }


async def prepare_lxc_template(
    config: LabEnvironmentConfig,
    *,
    execute: bool,
) -> dict[str, object]:
    if not config.enabled:
        return {"status": "skipped", "reason": config.skip_reason or "lab disabled"}
    client = build_lab_client(config)
    resources = DisposableProxmoxResources(client=client, node=config.node or "")
    storage = config.lxc_template_storage_id or config.storage_id or "local"
    discovered_template = await resources.first_lxc_template(storage)
    decision = await plan_lxc_template_preparation(
        config,
        discovered_template=discovered_template,
    )
    if not execute or decision["status"] != "bootstrap_required":
        return decision

    result = await client.post(
        f"/nodes/{config.node}/aplinfo",
        data={"storage": storage, "template": config.lxc_template_name},
    )
    await resources.wait_for_task(result)
    refreshed_template = await resources.first_lxc_template(storage)
    return await plan_lxc_template_preparation(
        config,
        discovered_template=refreshed_template,
    )


async def _main_async(output_file: Path | None, *, execute: bool) -> int:
    config = LabEnvironmentConfig.from_env(os.environ)
    result = await prepare_lxc_template(config, execute=execute)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output_file is not None:
        await asyncio.to_thread(_write_text, output_file, rendered)
    print(rendered, end="")
    return 0 if result["status"] in {"ready", "skipped", "bootstrap_required"} else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover or explicitly prepare a disposable lab LXC template."
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output-file", type=Path)
    args = parser.parse_args(argv)
    return asyncio.run(_main_async(args.output_file, execute=args.execute))


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
