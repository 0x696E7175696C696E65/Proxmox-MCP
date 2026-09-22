from __future__ import annotations

import re
from pathlib import Path
from typing import cast

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


def _full_registry() -> ToolRegistry:
    registry = ToolRegistry()
    register_internal_tools(registry)
    register_read_only_tools(registry)
    register_safe_mutation_tools(registry)
    register_dangerous_tools(registry)
    register_domain_completion_tools(registry)
    register_media_tools(registry)
    register_helper_script_tools(registry)
    register_ssh_tools(registry)
    return registry


def test_registered_tool_metadata_matches_tool_specification() -> None:
    registry = _full_registry()

    definitions = {definition.name: definition for definition in registry.definitions()}

    for row in _documented_tool_rows():
        definition = definitions.get(row.name)
        assert definition is not None, f"Missing documented tool: {row.name}"
        assert definition.permission == row.permission
        assert definition.risk == row.risk
        assert definition.dry_run is row.dry_run
        assert definition.connector == row.connector


def test_every_registered_tool_has_a_meaningful_description() -> None:
    registry = _full_registry()

    for definition in registry.definitions():
        description = definition.description.strip()
        # Descriptions are the only thing an MCP client sees to choose a tool, so they
        # must be more than a name echo.
        assert len(description) >= 25, (
            f"{definition.name} description is too short: {description!r}"
        )
        assert description.lower() != definition.name.replace("_", " ").lower()
        # Mention what the tool touches so agents can disambiguate similar names.
        assert (
            definition.permission.split(".", maxsplit=1)[0] in description.lower()
            or definition.category in description.lower()
            or "ssh" in description.lower()
        ), f"{definition.name} description lacks a domain hint: {description!r}"


def test_every_tool_exposes_a_per_tool_input_schema() -> None:
    registry = _full_registry()

    for definition in registry.definitions():
        schema = registry.fastmcp_input_schema(definition)
        properties = schema.get("properties", {})
        assert isinstance(properties, dict)
        properties = cast(dict[str, object], properties)
        # The agent-facing surface is {target, parameters, options} rather than an
        # opaque request envelope.
        assert "parameters" in properties, definition.name
        assert "options" in properties

        if definition.parameters_model is None:
            continue

        # Tools with a parameter model must surface that model as a concrete named schema
        # (a $ref into $defs) instead of a bare object, so callers see the exact keys.
        parameters_schema = properties["parameters"]
        assert isinstance(parameters_schema, dict)
        ref = cast(dict[str, object], parameters_schema).get("$ref")
        assert isinstance(ref, str), (
            f"{definition.name} parameters must reference a concrete schema"
        )
        def_name = ref.split("/")[-1]
        defs = schema.get("$defs", {})
        assert isinstance(defs, dict)
        assert def_name in defs, f"{definition.name} parameters $ref does not resolve"


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
