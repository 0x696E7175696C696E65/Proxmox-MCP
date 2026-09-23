"""Capability roles: per-tool allow/deny ACL on top of permission packs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


def _empty() -> frozenset[str]:
    return frozenset()


@dataclass(frozen=True, slots=True)
class CapabilityRole:
    """Named ACL: explicit tool grants with deny-wins overrides."""

    role_id: str
    name: str
    description: str = ""
    base_template: str | None = None
    granted_tools: frozenset[str] = field(default_factory=_empty)
    denied_tools: frozenset[str] = field(default_factory=_empty)
    permission_seeds: frozenset[str] = field(default_factory=_empty)
    system: bool = False
    version: int = 1

    def allows_tool(self, tool_name: str) -> bool:
        if _tool_matches_any(tool_name, self.denied_tools):
            return False
        if not self.granted_tools:
            return False
        return _tool_matches_any(tool_name, self.granted_tools)

    def grant_count(self) -> int:
        return len(self.granted_tools)

    def is_subset_of(self, other: CapabilityRole) -> bool:
        """True when this role cannot invoke anything other cannot (anti-escalation)."""
        if "*" in other.granted_tools and not other.denied_tools:
            return True
        if "*" in self.granted_tools:
            return "*" in other.granted_tools and self.denied_tools >= other.denied_tools
        for tool in self.granted_tools:
            if _tool_matches_any(tool, self.denied_tools):
                continue
            if not other.allows_tool(tool):
                return False
        return True


def _tool_matches_any(tool_name: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if pattern == "*" or pattern == tool_name:
            return True
        if pattern.endswith(".*"):
            prefix = pattern.removesuffix(".*")
            if tool_name == prefix or tool_name.startswith(f"{prefix}."):
                return True
        if pattern.endswith("*") and not pattern.endswith(".*"):
            prefix = pattern[:-1]
            if tool_name.startswith(prefix):
                return True
    return False


# Built-in templates keyed by coarse admin / MCP role names.
SYSTEM_TEMPLATE_IDS = {
    "viewer": "caprole_system_viewer",
    "operator": "caprole_system_operator",
    "admin": "caprole_system_admin",
    "read_only": "caprole_system_viewer",
    "cluster_admin": "caprole_system_cluster_admin",
    "administrator": "caprole_system_admin",
}


def system_capability_templates() -> tuple[CapabilityRole, ...]:
    """Immutable system templates (grants refined at seed time from tool catalog)."""
    return (
        CapabilityRole(
            role_id="caprole_system_viewer",
            name="Viewer",
            description="Read-only tools; deny-by-default for mutations.",
            base_template="viewer",
            granted_tools=frozenset(),
            denied_tools=frozenset(),
            permission_seeds=frozenset({"*.read", "audit.read", "approval.status.read"}),
            system=True,
        ),
        CapabilityRole(
            role_id="caprole_system_operator",
            name="Operator",
            description="Lifecycle and backup tools without destroy/wipe.",
            base_template="operator",
            granted_tools=frozenset(),
            denied_tools=frozenset(),
            permission_seeds=frozenset({"*.read", "vm.lifecycle.*", "lxc.lifecycle.*", "backup.*", "snapshot.*"}),
            system=True,
        ),
        CapabilityRole(
            role_id="caprole_system_cluster_admin",
            name="Cluster Admin",
            description="Broad cluster tools without SSH/helper or absolute admin.",
            base_template="cluster_admin",
            granted_tools=frozenset({"*"}),
            denied_tools=frozenset(),
            permission_seeds=frozenset({"*"}),
            system=True,
            version=1,
        ),
        CapabilityRole(
            role_id="caprole_system_admin",
            name="Administrator",
            description="Full tool access (break-glass). Prefer narrower custom roles.",
            base_template="admin",
            granted_tools=frozenset({"*"}),
            denied_tools=frozenset(),
            permission_seeds=frozenset({"*"}),
            system=True,
        ),
    )


def seed_grants_from_catalog(
    template: CapabilityRole,
    *,
    tool_names: Iterable[str],
    tool_permissions: dict[str, str],
    tool_risks: dict[str, str] | None = None,
) -> CapabilityRole:
    """Populate granted_tools from catalog using permission_seeds and risk filters."""
    if template.granted_tools:
        return template
    risks = tool_risks or {}
    granted: set[str] = set()
    for name in tool_names:
        permission = tool_permissions.get(name, "")
        risk = risks.get(name, "low")
        if template.base_template == "viewer":
            if risk != "low" and not permission.endswith(".read") and ".read" not in permission:
                continue
            if any(
                token in permission
                for token in (".write", ".destroy", ".delete", "lifecycle", "ssh.", "helper.script.execute")
            ):
                continue
            granted.add(name)
            continue
        if template.base_template == "operator":
            if any(
                token in permission
                for token in (".destroy", "disk.wipe", "permissions.write", "ssh.", "helper.script.execute")
            ):
                continue
            if risk == "critical":
                continue
            granted.add(name)
            continue
        granted.add(name)
    return CapabilityRole(
        role_id=template.role_id,
        name=template.name,
        description=template.description,
        base_template=template.base_template,
        granted_tools=frozenset(granted),
        denied_tools=template.denied_tools,
        permission_seeds=template.permission_seeds,
        system=template.system,
        version=template.version,
    )
