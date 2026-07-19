from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from string import Formatter
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, create_model

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolExecutionError, ToolRegistry

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_.:@!+-]+$")


class ProxmoxReadResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: object


def _empty_query_defaults() -> dict[str, object]:
    return {}


@dataclass(frozen=True, slots=True)
class ReadOnlyToolSpec:
    name: str
    category: str
    permission: str
    endpoint_template: str
    query_defaults: dict[str, object] = dataclass_field(default_factory=_empty_query_defaults)
    allowed_query_params: frozenset[str] = frozenset({"limit", "start"})
    # When set, list responses are projected to these fields plus identity fields, so a
    # metric-specific tool returns only the metric it names instead of the full blob.
    projection: frozenset[str] | None = None


# Identity fields always preserved when a projection is applied.
_PROJECTION_IDENTITY_FIELDS = frozenset({"id", "type", "node", "name", "status", "vmid", "storage"})


def _spec(
    name: str,
    category: str,
    permission: str,
    endpoint_template: str,
    *,
    query_defaults: dict[str, object] | None = None,
    allowed_query_params: frozenset[str] | None = None,
    projection: frozenset[str] | None = None,
) -> ReadOnlyToolSpec:
    return ReadOnlyToolSpec(
        name=name,
        category=category,
        permission=permission,
        endpoint_template=endpoint_template,
        query_defaults={} if query_defaults is None else query_defaults,
        allowed_query_params=frozenset({"limit", "start"})
        if allowed_query_params is None
        else allowed_query_params,
        projection=projection,
    )


READ_ONLY_TOOL_SPECS: tuple[ReadOnlyToolSpec, ...] = (
    _spec("get_cluster_status", "cluster", "cluster.status.read", "/cluster/status"),
    _spec("get_cluster_resources", "cluster", "cluster.resources.read", "/cluster/resources"),
    _spec("get_cluster_config", "cluster", "cluster.config.read", "/cluster/options"),
    _spec("get_cluster_membership", "cluster", "cluster.membership.read", "/cluster/status"),
    _spec("get_cluster_quorum", "cluster", "cluster.quorum.read", "/cluster/status"),
    _spec("list_cluster_tasks", "cluster", "cluster.tasks.read", "/cluster/tasks"),
    _spec("get_task_status", "cluster", "cluster.tasks.read", "/nodes/{node}/tasks/{upid}/status"),
    _spec("get_cluster_backup_schedule", "backup", "backup.job.read", "/cluster/backup"),
    _spec(
        "get_cluster_replication_jobs",
        "cluster",
        "cluster.replication.read",
        "/cluster/replication",
    ),
    _spec("list_nodes", "node", "node.inventory.read", "/nodes"),
    _spec("get_node_status", "node", "node.status.read", "/nodes/{node}/status"),
    _spec("get_node_version", "node", "node.status.read", "/nodes/{node}/version"),
    _spec("get_node_services", "node", "node.service.read", "/nodes/{node}/services"),
    _spec("get_node_updates", "node", "node.package.read", "/nodes/{node}/apt/update"),
    _spec("get_node_journal", "node", "node.logs.read", "/nodes/{node}/journal"),
    _spec("get_node_syslog", "node", "node.logs.read", "/nodes/{node}/syslog"),
    _spec("get_node_network_config", "network", "network.config.read", "/nodes/{node}/network"),
    _spec(
        "validate_node_network_config", "network", "network.config.read", "/nodes/{node}/network"
    ),
    _spec("get_node_time", "node", "node.status.read", "/nodes/{node}/time"),
    _spec(
        "list_vms", "vm", "vm.inventory.read", "/cluster/resources", query_defaults={"type": "qemu"}
    ),
    _spec("get_vm_status", "vm", "vm.status.read", "/nodes/{node}/qemu/{vmid}/status/current"),
    _spec("get_vm_config", "vm", "vm.config.read", "/nodes/{node}/qemu/{vmid}/config"),
    _spec(
        "list_lxc",
        "lxc",
        "lxc.inventory.read",
        "/cluster/resources",
        query_defaults={"type": "lxc"},
    ),
    _spec("get_lxc_status", "lxc", "lxc.status.read", "/nodes/{node}/lxc/{vmid}/status/current"),
    _spec("get_lxc_config", "lxc", "lxc.config.read", "/nodes/{node}/lxc/{vmid}/config"),
    _spec("list_storage", "storage", "storage.inventory.read", "/storage"),
    _spec(
        "get_storage_status",
        "storage",
        "storage.status.read",
        "/nodes/{node}/storage/{storage_id}/status",
    ),
    _spec(
        "get_storage_content",
        "storage",
        "storage.content.read",
        "/nodes/{node}/storage/{storage_id}/content",
    ),
    _spec("list_networks", "network", "network.config.read", "/nodes/{node}/network"),
    _spec("get_network_config", "network", "network.config.read", "/nodes/{node}/network"),
    _spec("list_sdn_zones", "network", "network.sdn.read", "/cluster/sdn/zones"),
    _spec("get_firewall_rules", "firewall", "firewall.rule.read", "/cluster/firewall/rules"),
    _spec("list_firewall_aliases", "firewall", "firewall.alias.read", "/cluster/firewall/aliases"),
    _spec("list_ipsets", "firewall", "firewall.ipset.read", "/cluster/firewall/ipset"),
    _spec("list_backup_jobs", "backup", "backup.job.read", "/cluster/backup"),
    _spec("list_backup_storage", "backup", "backup.storage.read", "/storage"),
    _spec(
        "get_backup_retention_policy", "backup", "backup.retention.read", "/cluster/backup/{job_id}"
    ),
    _spec("get_ceph_status", "ceph", "ceph.status.read", "/nodes/{node}/ceph/status"),
    _spec("get_ceph_health", "ceph", "ceph.health.read", "/nodes/{node}/ceph/status"),
    _spec("list_ceph_pools", "ceph", "ceph.pool.read", "/nodes/{node}/ceph/pools"),
    _spec("list_ceph_osds", "ceph", "ceph.osd.read", "/nodes/{node}/ceph/osd"),
    _spec("list_ceph_mons", "ceph", "ceph.mon.read", "/nodes/{node}/ceph/mon"),
    _spec("list_ceph_mgrs", "ceph", "ceph.mgr.read", "/nodes/{node}/ceph/mgr"),
    _spec("list_ha_resources", "ha", "ha.resource.read", "/cluster/ha/resources"),
    _spec("get_ha_status", "ha", "ha.status.read", "/cluster/ha/status/current"),
    _spec("list_ha_groups", "ha", "ha.group.read", "/cluster/ha/groups"),
    _spec("list_users", "user", "user.read", "/access/users"),
    _spec("list_groups", "group", "group.read", "/access/groups"),
    _spec("list_roles", "role", "role.read", "/access/roles"),
    _spec("list_permissions", "permission", "permission.read", "/access/permissions"),
    _spec(
        "get_cpu_metrics",
        "monitoring",
        "monitoring.cpu.read",
        "/cluster/resources",
        query_defaults={"type": "qemu"},
        projection=frozenset({"cpu", "maxcpu"}),
    ),
    _spec(
        "get_ram_metrics",
        "monitoring",
        "monitoring.ram.read",
        "/cluster/resources",
        query_defaults={"type": "qemu"},
        projection=frozenset({"mem", "maxmem"}),
    ),
    _spec(
        "get_network_metrics",
        "monitoring",
        "monitoring.network.read",
        "/cluster/resources",
        query_defaults={"type": "qemu"},
        projection=frozenset({"netin", "netout"}),
    ),
    _spec("get_ceph_metrics", "monitoring", "monitoring.ceph.read", "/nodes/{node}/ceph/status"),
)


def _read_only_description(spec: ReadOnlyToolSpec) -> str:
    path_fields = _template_fields(spec.endpoint_template)
    identity = (
        f" Provide {', '.join(path_fields)} via target (e.g. target.node, target.vmid, "
        "target.storage_id) or parameters."
        if path_fields
        else ""
    )
    if spec.projection is not None:
        fields = ", ".join(sorted(spec.projection))
        payload_desc = f"and returns per-resource {fields} (plus identity fields) under result.data"
    else:
        payload_desc = "and returns the raw Proxmox payload under result.data"
    return (
        f"Read-only {spec.category} discovery ({spec.permission}). Calls Proxmox API "
        f"GET {spec.endpoint_template} {payload_desc}.{identity} Never mutates state."
    )


def register_read_only_tools(registry: ToolRegistry) -> None:
    for spec in READ_ONLY_TOOL_SPECS:
        registry.register(
            ToolDefinition(
                name=spec.name,
                description=_read_only_description(spec),
                category=spec.category,
                permission=spec.permission,
                risk="low",
                dry_run=False,
                approval_default=False,
                connector="proxmox_api",
                handler=_build_read_only_handler(spec),
                parameters_model=_parameters_model_for(spec),
                result_model=ProxmoxReadResult,
            )
        )


def _build_read_only_handler(
    spec: ReadOnlyToolSpec,
) -> Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]:
    async def handler(request: ToolRequest, context: ToolExecutionContext) -> object:
        if context.proxmox_client is None:
            raise ToolExecutionError(
                error_code="PROXMOX_API_ERROR",
                message="Proxmox API client is not configured",
                retryable=False,
            )

        path = _format_endpoint(spec, request)
        params = _query_params_for(spec, request)
        try:
            data = await context.proxmox_client.get(path, params=params)
        except ProxmoxApiError as exc:
            raise ToolExecutionError(
                error_code=exc.error_code,
                message="Proxmox API request failed",
                details=exc.details,
                retryable=exc.retryable,
            ) from exc

        return {"data": _project_data(spec, data)}

    return handler


def _project_data(spec: ReadOnlyToolSpec, data: object) -> object:
    if spec.projection is None or not isinstance(data, list):
        return data
    keep = _PROJECTION_IDENTITY_FIELDS | spec.projection
    projected: list[object] = []
    for item in data:
        if isinstance(item, dict):
            projected.append({key: value for key, value in item.items() if key in keep})
        else:
            projected.append(item)
    return projected


def _format_endpoint(spec: ReadOnlyToolSpec, request: ToolRequest) -> str:
    values = {
        field: _path_value_for(field, request) for field in _template_fields(spec.endpoint_template)
    }
    for field, value in values.items():
        if value is None:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message=f"Missing required Proxmox path value: {field}",
            )
        _validate_path_segment(field, value)

    return spec.endpoint_template.format(**values)


def _path_value_for(field: str, request: ToolRequest) -> object | None:
    target_value = _target_path_value_for(field, request)
    parameter_value = request.parameters.get(field)
    if (
        target_value is not None
        and parameter_value is not None
        and str(parameter_value) != str(target_value)
    ):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Conflicting Proxmox path value: {field}",
        )

    return target_value if target_value is not None else parameter_value


def _target_path_value_for(field: str, request: ToolRequest) -> object | None:
    if field == "node":
        return request.target.node

    if field == "vmid":
        if (
            request.target.vmid is not None
            and request.target.resource_id.isdigit()
            and str(request.target.vmid) != request.target.resource_id
        ):
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message="Conflicting Proxmox target VM identity: vmid",
            )

        if request.target.vmid is not None:
            return request.target.vmid
        if request.target.resource_id.isdigit():
            return request.target.resource_id

    if field == "storage_id":
        if (
            request.target.storage_id is not None
            and request.target.resource_type == "storage"
            and request.target.storage_id != request.target.resource_id
        ):
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message="Conflicting Proxmox storage identity: storage_id",
            )

        if request.target.storage_id is not None:
            return request.target.storage_id
        if request.target.resource_type == "storage":
            return request.target.resource_id

    if field in {"upid", "job_id"}:
        return request.target.resource_id

    return None


def _query_params_for(spec: ReadOnlyToolSpec, request: ToolRequest) -> dict[str, object]:
    path_fields = set(_template_fields(spec.endpoint_template))
    query_params = dict(spec.query_defaults)
    allowed = spec.allowed_query_params | set(spec.query_defaults)
    for key, value in request.parameters.items():
        if key in path_fields:
            continue
        if key in spec.query_defaults:
            if value != spec.query_defaults[key]:
                raise ToolExecutionError(
                    error_code="INVALID_REQUEST",
                    message=f"Conflicting fixed Proxmox query value: {key}",
                )
            continue
        if key not in allowed:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message=f"Unsupported Proxmox query parameter: {key}",
            )
        query_params[key] = value

    return query_params


def _validate_path_segment(field: str, value: object) -> None:
    segment = str(value)
    if not _SAFE_SEGMENT.fullmatch(segment) or ".." in segment:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Invalid Proxmox path value: {field}",
        )


def _template_fields(template: str) -> tuple[str, ...]:
    return tuple(
        field_name for _, field_name, _, _ in Formatter().parse(template) if field_name is not None
    )


def _parameters_model_for(spec: ReadOnlyToolSpec) -> type[BaseModel]:
    field_names = sorted(
        set(_template_fields(spec.endpoint_template))
        | spec.allowed_query_params
        | set(spec.query_defaults)
    )
    fields = {name: (_field_type_for(name), None) for name in field_names}
    return create_model(
        f"{_pascal_case(spec.name)}Parameters",
        __config__=ConfigDict(extra="forbid"),
        **cast(dict[str, Any], fields),
    )


def _field_type_for(name: str) -> object:
    if name in {"vmid", "limit", "start"}:
        return int | None

    return str | None


def _pascal_case(value: str) -> str:
    return "".join(part.capitalize() for part in value.split("_"))
