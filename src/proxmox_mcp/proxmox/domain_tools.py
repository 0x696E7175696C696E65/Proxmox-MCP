from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, replace
from string import Formatter
from typing import Any, Literal, cast

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
    method: DomainMethod | None = None
    endpoint: str | None = None
    command: str | None = None
    payload: dict[str, object] = Field(default_factory=dict)
    result: object | None = None


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
    if name == "enter_lxc_console":
        return False
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
    _spec("enter_lxc_console", "lxc.console.open", "high", False, "hybrid"),
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
    _spec("reweight_ceph_osd", "ceph.osd.reweight", "high", True, "proxmox_api"),
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
    "update_sdn_zone": "/cluster/sdn/zones/{iface}",
    "create_vxlan": "/cluster/sdn/vnets",
    "update_firewall_rules": "/cluster/firewall/rules",
    "create_firewall_rule": "/cluster/firewall/rules",
    "delete_firewall_rule": "/cluster/firewall/rules/{iface}",
    "enable_firewall": "/cluster/firewall/options",
    "create_firewall_alias": "/cluster/firewall/aliases",
    "delete_firewall_alias": "/cluster/firewall/aliases/{iface}",
    "update_ipset": "/cluster/firewall/ipset/{iface}",
    "create_backup_job": "/cluster/backup",
    "update_backup_job": "/cluster/backup/{job_id}",
    "delete_backup_job": "/cluster/backup/{job_id}",
    "backup_vm": "/nodes/{node}/vzdump",
    "backup_lxc": "/nodes/{node}/vzdump",
    "restore_vm_backup": "/nodes/{node}/qemu",
    "restore_lxc_backup": "/nodes/{node}/lxc",
    "verify_backup": "/nodes/{node}/storage/{storage_id}/content/{volume}",
    "prune_backups": "/nodes/{node}/storage/{storage_id}/prunebackups",
    "manage_ceph_pool": "/nodes/{node}/ceph/pools/{pool}",
    "create_ceph_pool": "/nodes/{node}/ceph/pools",
    "create_ceph_osd": "/nodes/{node}/ceph/osd",
    "reweight_ceph_osd": "/nodes/{node}/ceph/osd/{osd_id}",
    "create_ceph_mon": "/nodes/{node}/ceph/mon",
    "delete_ceph_mon": "/nodes/{node}/ceph/mon/{iface}",
    "create_ha_resource": "/cluster/ha/resources",
    "update_ha_resource": "/cluster/ha/resources/{ha_resource_id}",
    "delete_ha_resource": "/cluster/ha/resources/{ha_resource_id}",
    "migrate_ha_resource": "/cluster/ha/resources/{ha_resource_id}/migrate",
    "set_ha_group": "/cluster/ha/groups/{ha_resource_id}",
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
    "get_disk_inventory": "lsblk -J",
    "test_firewall_policy": "pvesh get /cluster/firewall/rules",
    "get_cluster_health": "pvesh get /cluster/status",
    "get_disk_metrics": "lsblk -J",
    "get_zfs_health": "zpool status -x",
    "get_smart_data": "smartctl -a {device}",
    "run_diagnostics": "pvesh get /nodes/{node}/status",
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
                approval_default=spec.risk == "critical",
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


def _build_domain_handler(
    spec: DomainToolSpec,
) -> Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]:
    async def handler(request: ToolRequest, context: ToolExecutionContext) -> object:
        parameters = request.parameters
        payload = _payload_from_parameters(parameters)
        payload.update(_default_payload_for(spec))
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
            result = await _execute_ssh_command(command, request, context)
            return _result(
                spec,
                request,
                endpoint=endpoint,
                command=command,
                payload=payload,
                result=result.model_dump(mode="json"),
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


def _endpoint_for(
    spec: DomainToolSpec,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str | None:
    template = spec.endpoint_template
    if template is None:
        return None
    return _format_template(template, request, parameters)


def _command_for(
    spec: DomainToolSpec,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str | None:
    if spec.command_template is None:
        return None
    return _format_template(spec.command_template, request, parameters)


def _format_template(template: str, request: ToolRequest, parameters: dict[str, object]) -> str:
    values = {
        field: _template_value_for(field, request, parameters)
        for field in _template_fields(template)
    }
    for field, value in values.items():
        if value is None:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message=f"Missing required domain tool parameter: {field}",
            )
        _validate_path_segment(field, value)
    return template.format(**values)


def _template_value_for(
    field: str,
    request: ToolRequest,
    parameters: dict[str, object],
) -> str | None:
    explicit = parameters.get(field)
    if explicit is not None:
        return str(explicit)
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


def _validate_path_segment(field: str, value: str) -> None:
    if not _SAFE_SEGMENT.fullmatch(value) or ".." in value:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Unsafe domain tool path value for {field}",
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
        return await context.ssh_client.execute(
            SshTarget(
                cluster=request.target.cluster,
                node=request.target.node or request.target.resource_id,
            ),
            ssh_command,
        )
    except SshClientError as exc:
        raise ToolExecutionError(
            error_code=exc.error_code,
            message="SSH operation failed",
            details=exc.details,
            retryable=exc.retryable,
        ) from exc


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
        "method": spec.method,
        "endpoint": endpoint,
        "command": command,
        "payload": payload,
        "result": result,
    }
