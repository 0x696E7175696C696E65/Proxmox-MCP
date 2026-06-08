from __future__ import annotations

import re
from pathlib import Path

from proxmox_mcp.proxmox import (
    register_dangerous_tools,
    register_domain_completion_tools,
    register_helper_script_tools,
    register_media_tools,
    register_read_only_tools,
    register_safe_mutation_tools,
)
from proxmox_mcp.ssh.tools import register_ssh_tools
from proxmox_mcp.tools.internal import register_internal_tools
from proxmox_mcp.tools.registry import ToolRegistry


def test_registered_tool_metadata_matches_tool_specification() -> None:
    registry = ToolRegistry()
    register_internal_tools(registry)
    register_read_only_tools(registry)
    register_safe_mutation_tools(registry)
    register_dangerous_tools(registry)
    register_domain_completion_tools(registry)
    register_media_tools(registry)
    register_helper_script_tools(registry)
    register_ssh_tools(registry)

    definitions = {definition.name: definition for definition in registry.definitions()}

    for row in _documented_tool_rows():
        definition = definitions.get(row.name)
        assert definition is not None, f"Missing documented tool: {row.name}"
        assert definition.permission == row.permission
        assert definition.risk == row.risk
        assert definition.dry_run is row.dry_run
        assert definition.connector == row.connector


class ToolSpecRow:
    def __init__(
        self,
        *,
        name: str,
        permission: str,
        risk: str,
        dry_run: bool,
        connector: str,
    ) -> None:
        self.name = name
        self.permission = permission
        self.risk = risk
        self.dry_run = dry_run
        self.connector = connector


def _documented_tool_rows() -> tuple[ToolSpecRow, ...]:
    text = Path("docs/tool-specification.md").read_text(encoding="utf-8")
    rows: list[ToolSpecRow] = []
    for line in text.splitlines():
        match = re.match(
            r"\| `([^`]+)` \| `([^`]+)` \| ([^|]+) \| ([^|]+) \| ([^|]+) \|",
            line,
        )
        if match is None:
            continue
        name, permission, risk, dry_run, connector = match.groups()
        rows.append(
            ToolSpecRow(
                name=name,
                permission=permission,
                risk=risk.strip(),
                dry_run=dry_run.strip() == "true",
                connector=connector.strip(),
            )
        )
    return tuple(rows)
