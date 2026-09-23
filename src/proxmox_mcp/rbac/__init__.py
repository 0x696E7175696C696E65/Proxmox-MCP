from __future__ import annotations

from dataclasses import dataclass, field

from proxmox_mcp.auth import ActorIdentity

Permission = str


def _empty_permissions() -> frozenset[Permission]:
    return frozenset()


def _empty_strings() -> frozenset[str]:
    return frozenset()


@dataclass(frozen=True, slots=True)
class Role:
    name: str
    permissions: frozenset[Permission] = field(default_factory=_empty_permissions)
    denied_permissions: frozenset[Permission] = field(default_factory=_empty_permissions)
    # Tool ACL: None = permission-packs only (legacy); frozenset = deny-by-default grants.
    granted_tools: frozenset[str] | None = None
    denied_tools: frozenset[str] = field(default_factory=_empty_strings)

    @classmethod
    def read_only(cls) -> Role:
        return cls(
            name="ReadOnly",
            permissions=frozenset(
                {
                    "cluster.read",
                    "node.read",
                    "node.logs.read",
                    "vm.read",
                    "vm.config.read",
                    "lxc.read",
                    "lxc.config.read",
                    "storage.read",
                    "storage.iso.read",
                    "lxc.template.read",
                    "firewall.read",
                    "network.read",
                    "network.config.read",
                    "network.sdn.read",
                    "monitoring.read",
                    "monitoring.health.read",
                    "monitoring.cpu.read",
                    "monitoring.ram.read",
                    "monitoring.disk.read",
                    "monitoring.network.read",
                    "monitoring.zfs.read",
                    "monitoring.smart.read",
                    "monitoring.ceph.read",
                    "monitoring.metrics.read",
                    "monitoring.alerts.read",
                    "monitoring.trends.read",
                    "helper.catalog.read",
                    "helper.script.preview",
                    "helper.script.execution.read",
                    "user.read",
                    "group.read",
                    "role.read",
                    "permission.read",
                    "audit.read",
                    "approval.status.read",
                }
            ),
            granted_tools=None,
        )

    @classmethod
    def operator(cls) -> Role:
        return cls(
            name="Operator",
            permissions=Role.read_only().permissions
            | frozenset(
                {
                    "vm.lifecycle.*",
                    "lxc.lifecycle.*",
                    "vm.console.read",
                    "backup.run",
                    "snapshot.create",
                }
            ),
            denied_permissions=frozenset(
                {
                    "vm.lifecycle.destroy",
                    "lxc.lifecycle.destroy",
                }
            ),
        )

    @classmethod
    def administrator(cls) -> Role:
        return cls(
            name="Administrator",
            permissions=frozenset({"*"}),
            granted_tools=frozenset({"*"}),
        )

    @classmethod
    def cluster_admin(cls) -> Role:
        """Broad cluster ops without disk wipe, node power, or firewall disable."""
        return cls(
            name="ClusterAdmin",
            permissions=frozenset(
                {
                    "cluster.*",
                    "node.*",
                    "vm.*",
                    "lxc.*",
                    "storage.*",
                    "firewall.*",
                    "network.*",
                    "monitoring.*",
                    "user.read",
                    "group.read",
                    "role.read",
                    "permission.read",
                    "backup.*",
                    "snapshot.*",
                    "ha.*",
                    "ceph.*",
                    "sdn.*",
                    "media.*",
                    "helper.catalog.read",
                    "helper.script.preview",
                    "helper.script.execution.read",
                    "audit.read",
                    "approval.status.read",
                }
            ),
            denied_permissions=frozenset(
                {
                    "storage.disk.wipe",
                    "node.power.reboot",
                    "node.power.shutdown",
                    "firewall.config.write",
                    "vm.lifecycle.destroy",
                    "lxc.lifecycle.destroy",
                    "ceph.osd.remove",
                    "ceph.pool.delete",
                    "user.delete",
                    "permissions.write",
                    "permission.write",
                }
            ),
        )

    @classmethod
    def admin_console(cls) -> Role:
        """Admin UI invoke identity — least privilege, never *."""
        return cls(
            name="AdminConsole",
            permissions=Role.cluster_admin().permissions | Role.read_only().permissions,
            denied_permissions=Role.cluster_admin().denied_permissions
            | frozenset(
                {
                    "ssh.*",
                    "helper.*",
                }
            ),
        )


McpServiceRoleName = str


def role_from_mcp_name(name: str) -> Role:
    """Map settings role names to Role instances (MCP service-token bindings)."""
    normalized = name.strip().lower().replace("-", "_")
    mapping = {
        "read_only": Role.read_only,
        "readonly": Role.read_only,
        "operator": Role.operator,
        "cluster_admin": Role.cluster_admin,
        "clusteradmin": Role.cluster_admin,
        "administrator": Role.administrator,
        "admin": Role.administrator,
    }
    factory = mapping.get(normalized)
    if factory is None:
        raise ValueError(
            f"Unknown MCP service role {name!r}; expected one of "
            "read_only, operator, cluster_admin, administrator"
        )
    return factory()


@dataclass(frozen=True, slots=True)
class AccessTarget:
    resource_type: str
    resource_id: str | None = None
    tenant_id: str | None = None
    cluster: str | None = None
    node: str | None = None
    vmid: int | None = None
    storage_id: str | None = None


@dataclass(frozen=True, slots=True)
class Scope:
    tenant_id: str | None = None
    clusters: frozenset[str] = field(default_factory=_empty_strings)
    nodes: frozenset[str] = field(default_factory=_empty_strings)
    resource_type: str | None = None
    resource_ids: frozenset[str] = field(default_factory=_empty_strings)
    vmid_min: int | None = None
    vmid_max: int | None = None
    storage_ids: frozenset[str] = field(default_factory=_empty_strings)

    def matches(self, actor: ActorIdentity, target: AccessTarget) -> bool:
        if self.tenant_id is not None:
            if actor.tenant_id != self.tenant_id:
                return False

            if target.tenant_id != self.tenant_id:
                return False

        if self.clusters and target.cluster not in self.clusters:
            return False

        if self.nodes and target.node not in self.nodes:
            return False

        if self.resource_type is not None and target.resource_type != self.resource_type:
            return False

        if self.resource_ids and target.resource_id not in self.resource_ids:
            return False

        if not self._matches_vmid(target):
            return False

        if self.storage_ids and target.storage_id not in self.storage_ids:
            return False

        return True

    def _matches_vmid(self, target: AccessTarget) -> bool:
        if self.vmid_min is None and self.vmid_max is None:
            return True

        vmid = target.vmid
        if vmid is None and target.resource_id is not None:
            try:
                vmid = int(target.resource_id)
            except ValueError:
                return False

        if vmid is None:
            return False

        if self.vmid_min is not None and vmid < self.vmid_min:
            return False

        if self.vmid_max is not None and vmid > self.vmid_max:
            return False

        return True


@dataclass(frozen=True, slots=True)
class RoleAssignment:
    role: Role
    scope: Scope
    actor_user_id: str | None = None
    actor_agent_id: str | None = None

    def applies_to(self, actor: ActorIdentity) -> bool:
        if self.actor_user_id is not None and actor.user_id != self.actor_user_id:
            return False

        if self.actor_agent_id is not None and actor.agent_id != self.actor_agent_id:
            return False

        return True


class RBACEvaluator:
    def is_allowed(
        self,
        actor: ActorIdentity,
        permission: Permission,
        target: AccessTarget,
        assignments: tuple[RoleAssignment, ...],
    ) -> bool:
        return any(
            assignment.applies_to(actor)
            and assignment.scope.matches(actor, target)
            and self._role_allows(assignment.role, permission)
            for assignment in assignments
        )

    def _role_allows(self, role: Role, permission: Permission) -> bool:
        if any(_permission_matches(denied, permission) for denied in role.denied_permissions):
            return False
        return any(_permission_matches(granted, permission) for granted in role.permissions)

    def tool_allowed(self, role: Role, tool_name: str) -> bool:
        """Deny-by-default tool ACL when granted_tools is set; deny wins."""
        from proxmox_mcp.rbac.capability import _tool_matches_any

        if _tool_matches_any(tool_name, role.denied_tools):
            return False
        if role.granted_tools is None:
            return True
        if not role.granted_tools:
            return False
        return _tool_matches_any(tool_name, role.granted_tools)


def _permission_matches(granted: Permission, requested: Permission) -> bool:
    if granted == "*" or granted == requested:
        return True

    if granted.endswith(".*"):
        prefix = granted.removesuffix(".*")
        return requested == prefix or requested.startswith(f"{prefix}.")

    return False
