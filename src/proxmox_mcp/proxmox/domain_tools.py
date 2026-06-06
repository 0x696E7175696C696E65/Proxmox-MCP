from __future__ import annotations

import re
import shlex
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, replace
from hashlib import sha256
from string import Formatter
from typing import Any, Literal, cast
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, create_model

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.schemas.envelope import RiskLevel, ToolRequest
from proxmox_mcp.ssh.client import SshClientError, SshCommand, SshCommandResult, SshTarget
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import (
    ConnectorType,
    ToolDefinition,
    ToolExecutionError,
    ToolRegistry,
)

DomainMethod = Literal["GET", "POST", "PUT", "DELETE"]
PromotionStatus = Literal["live_supported", "guarded_not_implemented", "external_source_required"]
DomainPackName = Literal[
    "vm_lxc",
    "storage",
    "network_firewall",
    "backup",
    "ceph_ha",
    "ssh_console",
    "observability",
]
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_.:@!+,-]+$")
_TARGET_BACKED_FIELDS = frozenset({"node", "vmid", "storage_id"})
_READ_COMMAND_TOOLS = frozenset(
    {
        "get_node_hardware",
        "get_zfs_status",
        "get_disk_inventory",
        "get_cluster_health",
        "get_disk_metrics",
        "get_zfs_health",
        "get_smart_data",
        "test_firewall_policy",
        "run_diagnostics",
    }
)
_LIVE_COMMAND_TOOLS = frozenset(
    {
        "create_zfs_pool",
        "scrub_zfs_pool",
        "create_lvm_storage",
        "create_lvmthin_storage",
        "wipe_disk",
        "reweight_ceph_osd",
        "rebalance_ceph",
        "collect_support_bundle",
    }
)


_FIELD_TYPES: dict[str, Any] = {
    "node": str,
    "vmid": int | str,
    "storage_id": str,
    "service": str,
    "iface": str,
    "job_id": str,
    "volume": str,
    "device": str,
    "pool": str,
    "osd_id": int | str,
    "weight": int | float | str,
    "mon_id": str,
    "ha_group_id": str,
    "zone_id": str,
    "rule_id": int | str,
    "alias": str,
    "ipset": str,
    "userid": str,
    "groupid": str,
    "roleid": str,
    "ha_resource_id": str,
    "target_node": str,
}


class DomainToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool
    operation: str
    connector: ConnectorType
    risk: RiskLevel
    live_supported: bool
    promotion_status: PromotionStatus
    method: DomainMethod | None = None
    endpoint: str | None = None
    command: str | None = None
    payload: dict[str, object] = Field(default_factory=dict)
    impact: dict[str, object] = Field(default_factory=dict)
    rollback_guidance: str | None = None
    result: object | None = None


class DomainToolPromotionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    permission: str
    risk: RiskLevel
    connector: ConnectorType
    dry_run_supported: bool
    live_supported: bool
    promotion_status: PromotionStatus
    method: DomainMethod | None = None
    endpoint_template: str | None = None
    command_template: str | None = None
    path_fields: tuple[str, ...] = ()
    required_parameter_fields: tuple[str, ...] = ()
    payload_field: str
    failure_semantics: str
    lab_validation_required: bool


@dataclass(frozen=True, slots=True)
class DomainToolSpec:
    name: str
    category: str
    permission: str
    risk: RiskLevel
    dry_run: bool
    connector: ConnectorType
    method: DomainMethod | None = None
    endpoint_template: str | None = None
    command_template: str | None = None
    live_supported: bool = True


def _method_for(name: str, permission: str, dry_run: bool) -> DomainMethod | None:
    if not dry_run:
        return "GET"
    if name == "reload_node_networking":
        return "PUT"
    if name == "prune_backups":
        return "DELETE"
    if name.startswith(("delete_", "remove_")) or ".delete" in permission:
        return "DELETE"
    if name.startswith(("start_", "stop_", "restart_")):
        return "POST"
    if name.startswith("update_") or ".write" in permission:
        return "PUT"
    return "POST"


def _live_supported_for(name: str, dry_run: bool, connector: ConnectorType) -> bool:
    if connector == "internal":
        return name == "get_audit_events"
    if name in {"enter_lxc_console", "verify_backup"}:
        return False
    if name in _LIVE_COMMAND_TOOLS:
        return True
    if connector in {"ssh", "hybrid"} and dry_run and name not in _READ_COMMAND_TOOLS:
        return False
    return True


def _spec(
    name: str,
    permission: str,
    risk: RiskLevel,
    dry_run: bool,
    connector: ConnectorType,
) -> DomainToolSpec:
    return DomainToolSpec(
        name=name,
        category=permission.split(".", maxsplit=1)[0],
        permission=permission,
        risk=risk,
        dry_run=dry_run,
        connector=connector,
        method=_method_for(name, permission, dry_run),
        live_supported=_live_supported_for(name, dry_run, connector),
    )


DOMAIN_COMPLETION_TOOL_SPECS: tuple[DomainToolSpec, ...] = (
    _spec("join_cluster", "cluster.membership.write", "critical", True, "proxmox_api"),
    _spec("remove_cluster_node", "cluster.membership.delete", "critical", True, "proxmox_api"),
    _spec("update_cluster_options", "cluster.config.write", "high", True, "proxmox_api"),
    _spec("get_node_hardware", "node.hardware.read", "low", False, "hybrid"),
    _spec("start_node_service", "node.service.write", "medium", True, "proxmox_api"),
    _spec("stop_node_service", "node.service.write", "high", True, "proxmox_api"),
    _spec("restart_node_service", "node.service.write", "high", True, "proxmox_api"),
    _spec("apply_node_updates", "node.package.update", "high", True, "hybrid"),
    _spec("reload_node_networking", "network.config.apply", "critical", True, "proxmox_api"),
    _spec("create_vm", "vm.lifecycle.create", "high", True, "proxmox_api"),
    _spec("clone_vm", "vm.lifecycle.clone", "high", True, "proxmox_api"),
    _spec("reset_vm", "vm.lifecycle.reset", "high", True, "proxmox_api"),
    _spec("suspend_vm", "vm.lifecycle.suspend", "medium", True, "proxmox_api"),
    _spec("resume_vm", "vm.lifecycle.resume", "medium", True, "proxmox_api"),
    _spec("migrate_vm", "vm.lifecycle.migrate", "high", True, "proxmox_api"),
    _spec("force_migrate_vm", "vm.lifecycle.force_migrate", "critical", True, "proxmox_api"),
    _spec("snapshot_vm", "vm.snapshot.create", "medium", True, "proxmox_api"),
    _spec("restore_vm", "vm.backup.restore", "high", True, "proxmox_api"),
    _spec("resize_vm_disk", "vm.hardware.disk.resize", "high", True, "proxmox_api"),
    _spec("update_vm_hardware", "vm.hardware.write", "high", True, "proxmox_api"),
    _spec("set_vm_cloud_init", "vm.cloudinit.write", "medium", True, "proxmox_api"),
    _spec("create_lxc", "lxc.lifecycle.create", "high", True, "proxmox_api"),
    _spec("clone_lxc", "lxc.lifecycle.clone", "high", True, "proxmox_api"),
    _spec("suspend_lxc", "lxc.lifecycle.suspend", "medium", True, "proxmox_api"),
    _spec("resume_lxc", "lxc.lifecycle.resume", "medium", True, "proxmox_api"),
    _spec("snapshot_lxc", "lxc.snapshot.create", "medium", True, "proxmox_api"),
    _spec("restore_lxc", "lxc.backup.restore", "high", True, "proxmox_api"),
    _spec("update_lxc_resources", "lxc.resources.write", "medium", True, "proxmox_api"),
    _spec("enter_lxc_console", "lxc.console.open", "high", True, "hybrid"),
    _spec("create_storage", "storage.config.create", "high", True, "proxmox_api"),
    _spec("update_storage", "storage.config.write", "high", True, "proxmox_api"),
    _spec("expand_storage", "storage.capacity.expand", "high", True, "hybrid"),
    _spec("create_zfs_pool", "storage.zfs.create", "critical", True, "hybrid"),
    _spec("get_zfs_status", "storage.zfs.read", "low", False, "hybrid"),
    _spec("scrub_zfs_pool", "storage.zfs.scrub", "medium", True, "hybrid"),
    _spec("create_lvm_storage", "storage.lvm.create", "high", True, "hybrid"),
    _spec("create_lvmthin_storage", "storage.lvmthin.create", "high", True, "hybrid"),
    _spec("create_nfs_storage", "storage.nfs.create", "medium", True, "proxmox_api"),
    _spec("create_smb_storage", "storage.smb.create", "medium", True, "proxmox_api"),
    _spec("benchmark_storage", "storage.benchmark.run", "medium", True, "ssh"),
    _spec("move_volume", "storage.volume.move", "high", True, "proxmox_api"),
    _spec("copy_volume", "storage.volume.copy", "medium", True, "proxmox_api"),
    _spec("get_disk_inventory", "storage.disk.read", "low", False, "hybrid"),
    _spec("wipe_disk", "storage.disk.wipe", "critical", True, "hybrid"),
    _spec("create_bridge", "network.bridge.create", "high", True, "proxmox_api"),
    _spec("update_bridge", "network.bridge.write", "high", True, "proxmox_api"),
    _spec("delete_bridge", "network.bridge.delete", "critical", True, "proxmox_api"),
    _spec("create_bond", "network.bond.create", "high", True, "proxmox_api"),
    _spec("update_bond", "network.bond.write", "high", True, "proxmox_api"),
    _spec("delete_bond", "network.bond.delete", "critical", True, "proxmox_api"),
    _spec("create_vlan", "network.vlan.create", "medium", True, "proxmox_api"),
    _spec("update_vlan", "network.vlan.write", "medium", True, "proxmox_api"),
    _spec("delete_vlan", "network.vlan.delete", "high", True, "proxmox_api"),
    _spec("create_sdn_zone", "network.sdn.create", "high", True, "proxmox_api"),
    _spec("update_sdn_zone", "network.sdn.write", "high", True, "proxmox_api"),
    _spec("create_vxlan", "network.vxlan.create", "high", True, "proxmox_api"),
    _spec("update_firewall_rules", "firewall.rule.write", "high", True, "proxmox_api"),
    _spec("create_firewall_rule", "firewall.rule.create", "high", True, "proxmox_api"),
    _spec("delete_firewall_rule", "firewall.rule.delete", "high", True, "proxmox_api"),
    _spec("enable_firewall", "firewall.config.write", "high", True, "proxmox_api"),
    _spec("create_firewall_alias", "firewall.alias.create", "medium", True, "proxmox_api"),
    _spec("delete_firewall_alias", "firewall.alias.delete", "medium", True, "proxmox_api"),
    _spec("update_ipset", "firewall.ipset.write", "medium", True, "proxmox_api"),
    _spec("test_firewall_policy", "firewall.policy.test", "low", False, "hybrid"),
    _spec("create_backup_job", "backup.job.create", "medium", True, "proxmox_api"),
    _spec("update_backup_job", "backup.job.write", "medium", True, "proxmox_api"),
    _spec("delete_backup_job", "backup.job.delete", "high", True, "proxmox_api"),
    _spec("backup_vm", "backup.vm.create", "medium", True, "proxmox_api"),
    _spec("backup_lxc", "backup.lxc.create", "medium", True, "proxmox_api"),
    _spec("restore_vm_backup", "backup.vm.restore", "high", True, "proxmox_api"),
    _spec("restore_lxc_backup", "backup.lxc.restore", "high", True, "proxmox_api"),
    _spec("verify_backup", "backup.verify.run", "medium", True, "proxmox_api"),
    _spec("prune_backups", "backup.retention.prune", "high", True, "proxmox_api"),
    _spec("manage_ceph_pool", "ceph.pool.write", "high", True, "proxmox_api"),
    _spec("create_ceph_pool", "ceph.pool.create", "high", True, "proxmox_api"),
    _spec("create_ceph_osd", "ceph.osd.create", "high", True, "proxmox_api"),
    _spec("reweight_ceph_osd", "ceph.osd.reweight", "high", True, "hybrid"),
    _spec("create_ceph_mon", "ceph.mon.create", "high", True, "proxmox_api"),
    _spec("delete_ceph_mon", "ceph.mon.delete", "critical", True, "proxmox_api"),
    _spec("rebalance_ceph", "ceph.rebalance.run", "high", True, "hybrid"),
    _spec("create_ha_resource", "ha.resource.create", "high", True, "proxmox_api"),
    _spec("update_ha_resource", "ha.resource.write", "high", True, "proxmox_api"),
    _spec("delete_ha_resource", "ha.resource.delete", "high", True, "proxmox_api"),
    _spec("migrate_ha_resource", "ha.resource.migrate", "high", True, "proxmox_api"),
    _spec("set_ha_group", "ha.group.write", "high", True, "proxmox_api"),
    _spec("create_user", "user.create", "high", True, "proxmox_api"),
    _spec("update_user", "user.write", "high", True, "proxmox_api"),
    _spec("create_group", "group.create", "medium", True, "proxmox_api"),
    _spec("delete_group", "group.delete", "high", True, "proxmox_api"),
    _spec("create_role", "role.create", "high", True, "proxmox_api"),
    _spec("delete_role", "role.delete", "high", True, "proxmox_api"),
    _spec("update_permissions", "permission.write", "critical", True, "proxmox_api"),
    _spec("get_cluster_health", "monitoring.health.read", "low", False, "hybrid"),
    _spec("get_disk_metrics", "monitoring.disk.read", "low", False, "hybrid"),
    _spec("get_zfs_health", "monitoring.zfs.read", "low", False, "ssh"),
    _spec("get_smart_data", "monitoring.smart.read", "low", False, "ssh"),
    _spec("get_prometheus_metrics", "monitoring.metrics.read", "low", False, "internal"),
    _spec("get_recent_alerts", "monitoring.alerts.read", "low", False, "internal"),
    _spec("get_resource_trends", "monitoring.trends.read", "low", False, "internal"),
    _spec("run_diagnostics", "monitoring.diagnostics.run", "medium", True, "hybrid"),
    _spec("collect_support_bundle", "monitoring.support.collect", "high", True, "hybrid"),
    _spec("get_audit_events", "audit.event.read", "low", False, "internal"),
)


def domain_tool_promotion_records() -> tuple[DomainToolPromotionRecord, ...]:
    return tuple(
        _promotion_record_for(_resolve_execution_spec(spec))
        for spec in DOMAIN_COMPLETION_TOOL_SPECS
    )


DOMAIN_TOOL_PACKS: dict[DomainPackName, tuple[str, ...]] = {
    "vm_lxc": (
        "create_vm",
        "clone_vm",
        "reset_vm",
        "suspend_vm",
        "resume_vm",
        "migrate_vm",
        "force_migrate_vm",
        "snapshot_vm",
        "restore_vm",
        "resize_vm_disk",
        "update_vm_hardware",
        "set_vm_cloud_init",
        "create_lxc",
        "clone_lxc",
        "suspend_lxc",
        "resume_lxc",
        "snapshot_lxc",
        "restore_lxc",
        "update_lxc_resources",
        "enter_lxc_console",
    ),
    "storage": (
        "create_storage",
        "update_storage",
        "expand_storage",
        "create_zfs_pool",
        "get_zfs_status",
        "scrub_zfs_pool",
        "create_lvm_storage",
        "create_lvmthin_storage",
        "create_nfs_storage",
        "create_smb_storage",
        "benchmark_storage",
        "move_volume",
        "copy_volume",
        "get_disk_inventory",
        "wipe_disk",
    ),
    "network_firewall": (
        "reload_node_networking",
        "create_bridge",
        "update_bridge",
        "delete_bridge",
        "create_bond",
        "update_bond",
        "delete_bond",
        "create_vlan",
        "update_vlan",
        "delete_vlan",
        "create_sdn_zone",
        "update_sdn_zone",
        "create_vxlan",
        "update_firewall_rules",
        "create_firewall_rule",
        "delete_firewall_rule",
        "enable_firewall",
        "create_firewall_alias",
        "delete_firewall_alias",
        "update_ipset",
        "test_firewall_policy",
    ),
    "backup": (
        "create_backup_job",
        "update_backup_job",
        "delete_backup_job",
        "backup_vm",
        "backup_lxc",
        "restore_vm_backup",
        "restore_lxc_backup",
        "verify_backup",
        "prune_backups",
    ),
    "ceph_ha": (
        "manage_ceph_pool",
        "create_ceph_pool",
        "create_ceph_osd",
        "reweight_ceph_osd",
        "create_ceph_mon",
        "delete_ceph_mon",
        "rebalance_ceph",
        "create_ha_resource",
        "update_ha_resource",
        "delete_ha_resource",
        "migrate_ha_resource",
        "set_ha_group",
    ),
    "ssh_console": (
        "enter_lxc_console",
        "run_diagnostics",
        "collect_support_bundle",
    ),
    "observability": (
        "get_cluster_health",
        "get_disk_metrics",
        "get_zfs_health",
        "get_smart_data",
        "get_prometheus_metrics",
        "get_recent_alerts",
        "get_resource_trends",
        "get_audit_events",
    ),
}


def domain_tool_pack_records(pack: DomainPackName) -> tuple[DomainToolPromotionRecord, ...]:
    records = {record.name: record for record in domain_tool_promotion_records()}
    return tuple(records[name] for name in DOMAIN_TOOL_PACKS[pack])


_ENDPOINT_TEMPLATES: dict[str, str] = {
    "join_cluster": "/cluster/config/join",
    "remove_cluster_node": "/cluster/config/nodes/{node}",
    "update_cluster_options": "/cluster/options",
    "start_node_service": "/nodes/{node}/services/{service}/state",
    "stop_node_service": "/nodes/{node}/services/{service}/state",
    "restart_node_service": "/nodes/{node}/services/{service}/state",
    "reload_node_networking": "/nodes/{node}/network",
    "create_vm": "/nodes/{node}/qemu",
    "clone_vm": "/nodes/{node}/qemu/{vmid}/clone",
    "reset_vm": "/nodes/{node}/qemu/{vmid}/status/reset",
    "suspend_vm": "/nodes/{node}/qemu/{vmid}/status/suspend",
    "resume_vm": "/nodes/{node}/qemu/{vmid}/status/resume",
    "migrate_vm": "/nodes/{node}/qemu/{vmid}/migrate",
    "force_migrate_vm": "/nodes/{node}/qemu/{vmid}/migrate",
    "snapshot_vm": "/nodes/{node}/qemu/{vmid}/snapshot",
    "restore_vm": "/nodes/{node}/qemu",
    "resize_vm_disk": "/nodes/{node}/qemu/{vmid}/resize",
    "update_vm_hardware": "/nodes/{node}/qemu/{vmid}/config",
    "set_vm_cloud_init": "/nodes/{node}/qemu/{vmid}/config",
    "create_lxc": "/nodes/{node}/lxc",
    "clone_lxc": "/nodes/{node}/lxc/{vmid}/clone",
    "suspend_lxc": "/nodes/{node}/lxc/{vmid}/status/suspend",
    "resume_lxc": "/nodes/{node}/lxc/{vmid}/status/resume",
    "snapshot_lxc": "/nodes/{node}/lxc/{vmid}/snapshot",
    "restore_lxc": "/nodes/{node}/lxc",
    "update_lxc_resources": "/nodes/{node}/lxc/{vmid}/config",
    "create_storage": "/storage",
    "update_storage": "/storage/{storage_id}",
    "create_nfs_storage": "/storage",
    "create_smb_storage": "/storage",
    "move_volume": "/nodes/{node}/storage/{storage_id}/content/{volume}",
    "copy_volume": "/nodes/{node}/storage/{storage_id}/content/{volume}",
    "create_bridge": "/nodes/{node}/network",
    "update_bridge": "/nodes/{node}/network/{iface}",
    "delete_bridge": "/nodes/{node}/network/{iface}",
    "create_bond": "/nodes/{node}/network",
    "update_bond": "/nodes/{node}/network/{iface}",
    "delete_bond": "/nodes/{node}/network/{iface}",
    "create_vlan": "/nodes/{node}/network",
    "update_vlan": "/nodes/{node}/network/{iface}",
    "delete_vlan": "/nodes/{node}/network/{iface}",
    "create_sdn_zone": "/cluster/sdn/zones",
    "update_sdn_zone": "/cluster/sdn/zones/{zone_id}",
    "create_vxlan": "/cluster/sdn/vnets",
    "update_firewall_rules": "/cluster/firewall/rules",
    "create_firewall_rule": "/cluster/firewall/rules",
    "delete_firewall_rule": "/cluster/firewall/rules/{rule_id}",
    "enable_firewall": "/cluster/firewall/options",
    "create_firewall_alias": "/cluster/firewall/aliases",
    "delete_firewall_alias": "/cluster/firewall/aliases/{alias}",
    "update_ipset": "/cluster/firewall/ipset/{ipset}",
    "create_backup_job": "/cluster/backup",
    "update_backup_job": "/cluster/backup/{job_id}",
    "delete_backup_job": "/cluster/backup/{job_id}",
    "backup_vm": "/nodes/{node}/vzdump",
    "backup_lxc": "/nodes/{node}/vzdump",
    "restore_vm_backup": "/nodes/{node}/qemu",
    "restore_lxc_backup": "/nodes/{node}/lxc",
    "verify_backup": "/nodes/{node}/storage/{storage_id}/content/{volume}",
    "prune_backups": "/nodes/{node}/storage/{storage_id}/prunebackups",
    "manage_ceph_pool": "/nodes/{node}/ceph/pool/{pool}",
    "create_ceph_pool": "/nodes/{node}/ceph/pool",
    "create_ceph_osd": "/nodes/{node}/ceph/osd",
    "create_ceph_mon": "/nodes/{node}/ceph/mon",
    "delete_ceph_mon": "/nodes/{node}/ceph/mon/{mon_id}",
    "create_ha_resource": "/cluster/ha/resources",
    "update_ha_resource": "/cluster/ha/resources/{ha_resource_id}",
    "delete_ha_resource": "/cluster/ha/resources/{ha_resource_id}",
    "migrate_ha_resource": "/cluster/ha/resources/{ha_resource_id}/migrate",
    "set_ha_group": "/cluster/ha/groups/{ha_group_id}",
    "create_user": "/access/users",
    "update_user": "/access/users/{userid}",
    "create_group": "/access/groups",
    "delete_group": "/access/groups/{groupid}",
    "create_role": "/access/roles",
    "delete_role": "/access/roles/{roleid}",
    "update_permissions": "/access/acl",
}

_COMMAND_TEMPLATES: dict[str, str] = {
    "get_node_hardware": "pvesh get /nodes/{node}/hardware/pci",
    "get_zfs_status": "zpool status -x",
    "create_zfs_pool": "zpool create {pool} {device}",
    "scrub_zfs_pool": "zpool scrub {pool}",
    "create_lvm_storage": "pvesm add lvm {storage_id} --vgname {volume}",
    "create_lvmthin_storage": (
        "pvesm add lvmthin {storage_id} --vgname {volume} --thinpool {pool}"
    ),
    "get_disk_inventory": "lsblk -J",
    "wipe_disk": "wipefs -a {device}",
    "reweight_ceph_osd": "ceph osd reweight {osd_id} {weight}",
    "rebalance_ceph": "ceph osd reweight-by-utilization",
    "test_firewall_policy": "pvesh get /cluster/firewall/rules",
    "get_cluster_health": "pvesh get /cluster/status",
    "get_disk_metrics": "lsblk -J",
    "get_zfs_health": "zpool status -x",
    "get_smart_data": "smartctl -a {device}",
    "enter_lxc_console": "pct enter {vmid}",
    "run_diagnostics": "pvesh get /nodes/{node}/status",
    "collect_support_bundle": "pveversion -v",
}


def register_domain_completion_tools(registry: ToolRegistry) -> None:
    for spec in DOMAIN_COMPLETION_TOOL_SPECS:
        spec = _resolve_execution_spec(spec)
        registry.register(
            ToolDefinition(
                name=spec.name,
                category=spec.category,
                permission=spec.permission,
                risk=spec.risk,
                dry_run=spec.dry_run,
                approval_default=_approval_default_for(spec),
                connector=spec.connector,
                handler=_build_domain_handler(spec),
                parameters_model=_parameters_model_for(spec),
                result_model=DomainToolResult,
            )
        )


def _resolve_execution_spec(spec: DomainToolSpec) -> DomainToolSpec:
    resolved = replace(
        spec,
        endpoint_template=spec.endpoint_template or _ENDPOINT_TEMPLATES.get(spec.name),
        command_template=spec.command_template or _COMMAND_TEMPLATES.get(spec.name),
    )
    if resolved.connector == "proxmox_api" and resolved.endpoint_template is None:
        raise RuntimeError(f"Domain tool {resolved.name} lacks a Proxmox endpoint template")
    if (
        resolved.connector == "ssh"
        and resolved.live_supported
        and resolved.command_template is None
    ):
        raise RuntimeError(f"Domain tool {resolved.name} lacks an SSH command template")
    if (
        resolved.connector == "hybrid"
        and resolved.live_supported
        and resolved.endpoint_template is None
        and resolved.command_template is None
    ):
        raise RuntimeError(f"Domain tool {resolved.name} lacks a hybrid execution target")
    return resolved


def _approval_default_for(spec: DomainToolSpec) -> bool:
    if spec.risk == "critical":
        return True
    return spec.risk == "high" and (
        spec.name.startswith(("delete_", "remove_", "force_"))
        or spec.name in {"prune_backups", "wipe_disk"}
        or spec.permission.endswith((".delete", ".prune", ".wipe"))
    )


def _promotion_record_for(spec: DomainToolSpec) -> DomainToolPromotionRecord:
    path_fields = tuple(
        sorted(
            set(_template_fields(spec.endpoint_template or ""))
            | set(_template_fields(spec.command_template or ""))
        )
    )
    required_fields = tuple(field for field in path_fields if field not in _TARGET_BACKED_FIELDS)
    return DomainToolPromotionRecord(
        name=spec.name,
        permission=spec.permission,
        risk=spec.risk,
        connector=spec.connector,
        dry_run_supported=spec.dry_run,
        live_supported=spec.live_supported,
        promotion_status=_promotion_status_for(spec),
        method=spec.method,
        endpoint_template=spec.endpoint_template,
        command_template=spec.command_template,
        path_fields=path_fields,
        required_parameter_fields=required_fields,
        payload_field="payload",
        failure_semantics=_failure_semantics_for(spec),
        lab_validation_required=spec.connector != "internal",
    )


def _promotion_status_for(spec: DomainToolSpec) -> PromotionStatus:
    if spec.live_supported:
        return "live_supported"
    if spec.connector == "internal":
        return "external_source_required"
    return "guarded_not_implemented"


def _failure_semantics_for(spec: DomainToolSpec) -> str:
    if not spec.live_supported:
        return (
            "Live execution returns NOT_IMPLEMENTED until endpoint, schema, and lab evidence exist"
        )
    if spec.connector == "proxmox_api":
        return "Connector failures return structured Proxmox API errors with retryability"
    if spec.connector in {"ssh", "hybrid"}:
        return "SSH policy, connection, and command failures return structured SSH errors"
    return "Internal telemetry requires a configured queryable source"


def _build_domain_handler(
    spec: DomainToolSpec,
) -> Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]:
    async def handler(request: ToolRequest, context: ToolExecutionContext) -> object:
        _validate_target_consistency(request)
        parameters = request.parameters
        payload = _payload_from_parameters(parameters)
        payload.update(_default_payload_for(spec))
        payload = _payload_for_execution(spec, request, payload)
        endpoint = _endpoint_for(spec, request, parameters)
        command = _command_for(spec, request, parameters)

        if request.options.dry_run:
            return _result(spec, request, endpoint=endpoint, command=command, payload=payload)

        if not spec.live_supported:
            raise ToolExecutionError(
                error_code="NOT_IMPLEMENTED",
                message="Domain tool live execution is not implemented",
                details={"tool_name": spec.name, "connector": spec.connector},
            )

        if spec.connector == "internal":
            return _result(
                spec,
                request,
                endpoint=endpoint,
                command=command,
                payload=payload,
                result=_internal_result_for(spec, context),
            )

        if command is not None and spec.connector in {"ssh", "hybrid"}:
            result = await _execute_ssh_command(spec, command, request, context)
            result_payload = _ssh_result_payload_for(spec, command, result, context)
            return _result(
                spec,
                request,
                endpoint=endpoint,
                command=command,
                payload=payload,
                result=result_payload,
            )

        data = await _execute_proxmox_request(spec, endpoint, payload, context)
        return _result(
            spec, request, endpoint=endpoint, command=command, payload=payload, result=data
        )

    return handler


def _default_payload_for(spec: DomainToolSpec) -> dict[str, object]:
    if spec.name == "start_node_service":
        return {"state": "started"}
    if spec.name == "stop_node_service":
        return {"state": "stopped"}
    if spec.name == "restart_node_service":
        return {"state": "restart"}
    if spec.name == "enable_firewall":
        return {"enable": 1}
    if spec.name == "force_migrate_vm":
        return {"force": 1}
    return {}


def _payload_for_execution(
    spec: DomainToolSpec,
    request: ToolRequest,
    payload: dict[str, object],
) -> dict[str, object]:
    if spec.name != "prune_backups":
        return payload

    if request.target.resource_type in {"vm", "lxc"}:
        vmid = _target_backed_value_for("vmid", request)
        if vmid is None:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message="Backup prune for guest targets requires a VMID target",
            )
        supplied_vmid = payload.get("vmid")
        if supplied_vmid is not None and str(supplied_vmid) != vmid:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message="Backup prune payload vmid must match the authorized target",
            )
        scoped_payload = dict(payload)
        scoped_payload["vmid"] = vmid
        scoped_payload.setdefault(
            "type", "lxc" if request.target.resource_type == "lxc" else "qemu"
        )
        return scoped_payload

    if request.target.resource_type == "storage":
        return payload

    raise ToolExecutionError(
        error_code="INVALID_REQUEST",
        message="Backup prune requires a storage, VM, or LXC target",
    )


def _validate_target_consistency(request: ToolRequest) -> None:
    target = request.target
    if target.resource_type in {"vm", "lxc"} and target.vmid is not None:
        _raise_if_target_mismatch("vmid", target.resource_id, str(target.vmid))
    if target.resource_type == "storage" and target.storage_id is not None:
        _raise_if_target_mismatch("storage_id", target.resource_id, target.storage_id)
    if target.resource_type == "node" and target.node is not None:
        _raise_if_target_mismatch("node", target.resource_id, target.node)


def _raise_if_target_mismatch(field: str, resource_id: str, value: str) -> None:
    if resource_id != value:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Target {field} must match target resource_id",
        )


def _endpoint_for(
    spec: DomainToolSpec,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str | None:
    template = spec.endpoint_template
    if template is None:
        return None
    return _format_endpoint_template(template, request, parameters)


def _command_for(
    spec: DomainToolSpec,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str | None:
    if spec.command_template is None:
        return None
    return _format_command_template(spec.command_template, request, parameters)


def _format_endpoint_template(
    template: str,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str:
    values = {
        field: _endpoint_value_for(field, request, parameters)
        for field in _template_fields(template)
    }
    return template.format(**values)


def _format_command_template(
    template: str,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str:
    values = {
        field: _command_value_for(field, request, parameters)
        for field in _template_fields(template)
    }
    return template.format(**values)


def _endpoint_value_for(
    field: str,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str:
    value = _template_value_for(field, request, parameters)
    _validate_endpoint_segment(field, value)
    return quote(value, safe="")


def _command_value_for(
    field: str,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str:
    value = _template_value_for(field, request, parameters)
    _validate_command_argument(field, value)
    return shlex.quote(value)


def _template_value_for(
    field: str,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str:
    explicit = parameters.get(field)
    target_value = _target_backed_value_for(field, request)
    if target_value is not None:
        if explicit is not None and str(explicit) != target_value:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message=f"Domain tool parameter {field} must match the authorized target",
            )
        return target_value
    if explicit is not None:
        return str(explicit)
    raise ToolExecutionError(
        error_code="INVALID_REQUEST",
        message=f"Missing required domain tool parameter: {field}",
    )


def _target_backed_value_for(field: str, request: ToolRequest) -> str | None:
    if field == "node":
        return request.target.node
    if field == "vmid":
        if request.target.vmid is not None:
            return str(request.target.vmid)
        if request.target.resource_type in {"vm", "lxc"}:
            return request.target.resource_id
    if field == "storage_id":
        if request.target.storage_id is not None:
            return request.target.storage_id
        if request.target.resource_type == "storage":
            return request.target.resource_id
    return None


def _validate_endpoint_segment(field: str, value: str) -> None:
    if ".." in value or "\x00" in value or "\n" in value or "\r" in value:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Unsafe domain tool path value for {field}",
        )
    if field == "volume":
        return
    if not _SAFE_SEGMENT.fullmatch(value):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Unsafe domain tool path value for {field}",
        )


def _validate_command_argument(field: str, value: str) -> None:
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Unsafe domain tool command value for {field}",
        )
    if value.startswith("-"):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Domain tool command value for {field} must be positional",
        )
    if field == "device" and ".." in value:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Unsafe domain tool command value for {field}",
        )


def _template_fields(template: str) -> tuple[str, ...]:
    return tuple(
        field_name for _, field_name, _, _ in Formatter().parse(template) if field_name is not None
    )


def _parameters_model_for(spec: DomainToolSpec) -> type[BaseModel]:
    path_fields = frozenset(
        _template_fields(spec.endpoint_template or "")
        + _template_fields(spec.command_template or "")
    )
    fields: dict[str, tuple[Any, object]] = {
        "payload": (dict[str, object], Field(default_factory=dict))
    }
    for field in sorted(path_fields):
        default: object = None if field in _TARGET_BACKED_FIELDS else ...
        fields[field] = (_FIELD_TYPES[field], default)

    model_name = "".join(part.capitalize() for part in spec.name.split("_")) + "Parameters"
    return create_model(
        model_name,
        __config__=ConfigDict(extra="forbid"),
        **cast(dict[str, Any], fields),
    )


def _payload_from_parameters(parameters: dict[str, object]) -> dict[str, object]:
    payload = parameters.get("payload", {})
    if isinstance(payload, dict):
        return dict(cast(dict[str, object], payload))
    raise ToolExecutionError(
        error_code="INVALID_REQUEST",
        message="Domain tool payload must be an object",
    )


def _ssh_result_payload_for(
    spec: DomainToolSpec,
    command: str,
    result: SshCommandResult,
    context: ToolExecutionContext,
) -> dict[str, object]:
    command_hash = sha256(command.encode()).hexdigest()
    context.audit_metadata["ssh_command_hash"] = command_hash
    context.audit_metadata["ssh_exit_status"] = result.exit_status
    payload = result.model_dump(mode="json")
    if spec.risk in {"high", "critical"}:
        payload["stdout"] = ""
        payload["stderr"] = ""
        payload["redacted"] = True
    else:
        payload["redacted"] = False
    payload["command_hash"] = command_hash
    return payload


async def _execute_proxmox_request(
    spec: DomainToolSpec,
    endpoint: str | None,
    payload: dict[str, object],
    context: ToolExecutionContext,
) -> object:
    if endpoint is None or spec.method is None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Domain tool does not define a Proxmox request",
        )
    if context.proxmox_client is None:
        raise ToolExecutionError(
            error_code="PROXMOX_API_ERROR",
            message="Proxmox API client is not configured",
            retryable=False,
        )
    try:
        if spec.method == "GET":
            return await context.proxmox_client.get(endpoint, params=payload)
        if spec.method == "POST":
            return await context.proxmox_client.post(endpoint, data=payload)
        if spec.method == "PUT":
            return await context.proxmox_client.put(endpoint, data=payload)
        return await context.proxmox_client.delete(endpoint, data=payload)
    except ProxmoxApiError as exc:
        raise ToolExecutionError(
            error_code=exc.error_code,
            message="Proxmox API request failed",
            details=exc.details,
            retryable=exc.retryable,
        ) from exc


async def _execute_ssh_command(
    spec: DomainToolSpec,
    command: str,
    request: ToolRequest,
    context: ToolExecutionContext,
) -> SshCommandResult:
    if context.ssh_client is None:
        raise ToolExecutionError(
            error_code="SSH_CONNECTION_FAILED",
            message="SSH client is not configured",
            retryable=False,
        )
    ssh_command = SshCommand(command=command)
    if context.ssh_command_policy is not None:
        decision = context.ssh_command_policy.evaluate(ssh_command)
        if not decision.allowed:
            raise ToolExecutionError(
                error_code="SSH_POLICY_DENIED",
                message="SSH command denied by policy",
                details={"reason": decision.reason, "executable": decision.executable},
            )
    try:
        result = await context.ssh_client.execute(
            SshTarget(
                cluster=request.target.cluster,
                node=request.target.node or request.target.resource_id,
            ),
            ssh_command,
        )
        if result.exit_status != 0:
            raise ToolExecutionError(
                error_code="SSH_COMMAND_FAILED",
                message="SSH command returned a non-zero exit status",
                details=_ssh_failure_details_for(spec, command, result),
                retryable=False,
            )
        return result
    except SshClientError as exc:
        raise ToolExecutionError(
            error_code=exc.error_code,
            message="SSH operation failed",
            details=exc.details,
            retryable=exc.retryable,
        ) from exc


def _ssh_failure_details_for(
    spec: DomainToolSpec,
    command: str,
    result: SshCommandResult,
) -> dict[str, object]:
    details: dict[str, object] = {
        "exit_status": result.exit_status,
        "command_hash": sha256(command.encode()).hexdigest(),
    }
    if spec.risk in {"high", "critical"}:
        details["redacted"] = True
        return details
    details["stdout"] = result.stdout
    details["stderr"] = result.stderr
    details["redacted"] = False
    return details


def _internal_result_for(spec: DomainToolSpec, context: ToolExecutionContext) -> object:
    if spec.name == "get_audit_events":
        events = getattr(context.audit_writer, "events", None)
        if not isinstance(events, Iterable):
            raise ToolExecutionError(
                error_code="NOT_IMPLEMENTED",
                message="Audit event querying requires a configured audit repository",
            )

        serialized: list[object] = []
        for event in cast(Iterable[object], events):
            if isinstance(event, BaseModel):
                serialized.append(event.model_dump(mode="json"))
            else:
                serialized.append(str(event))
        return serialized
    raise ToolExecutionError(
        error_code="NOT_IMPLEMENTED",
        message="Internal domain telemetry source is not configured",
        details={"tool_name": spec.name},
    )


def _result(
    spec: DomainToolSpec,
    request: ToolRequest,
    *,
    endpoint: str | None,
    command: str | None,
    payload: dict[str, object],
    result: object | None = None,
) -> dict[str, object]:
    return {
        "dry_run": request.options.dry_run,
        "operation": spec.permission,
        "connector": spec.connector,
        "risk": spec.risk,
        "live_supported": spec.live_supported,
        "promotion_status": _promotion_status_for(spec),
        "method": spec.method,
        "endpoint": endpoint,
        "command": command,
        "payload": payload,
        "impact": _impact_for(spec, request),
        "rollback_guidance": _rollback_guidance_for(spec),
        "result": result,
    }


def _impact_for(spec: DomainToolSpec, request: ToolRequest) -> dict[str, object]:
    return {
        "risk": spec.risk,
        "resource": {
            "cluster": request.target.cluster,
            "node": request.target.node,
            "resource_type": request.target.resource_type,
            "resource_id": request.target.resource_id,
        },
        "requires_lab_validation": spec.connector != "internal",
        "live_supported": spec.live_supported,
    }


def _rollback_guidance_for(spec: DomainToolSpec) -> str | None:
    if not spec.dry_run:
        return None
    if spec.risk == "critical":
        return (
            "Require a verified backup, console access, and a documented rollback "
            "window before live execution"
        )
    if spec.risk == "high":
        return "Verify target state and rollback path before live execution"
    if spec.risk == "medium":
        return "Confirm expected state and monitor the resulting Proxmox task"
    return "Read-only or low-risk operation; no rollback action expected"
