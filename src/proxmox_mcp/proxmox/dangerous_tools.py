from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from string import Formatter
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, create_model

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolExecutionError, ToolRegistry

DangerousMutationMethod = Literal["POST", "PUT", "DELETE"]
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_.:@!+,-]+$")


class DangerousMutationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool
    operation: str
    method: DangerousMutationMethod
    endpoint: str
    payload: dict[str, object]
    impact: dict[str, object]
    target_revalidated: bool = False
    revalidation_endpoint: str | None = None
    result: object | None = None


def _empty_payload_fields() -> frozenset[str]:
    return frozenset()


def _empty_payload_defaults() -> dict[str, object]:
    return {}


def _empty_suggestions() -> tuple[str, ...]:
    return ()


@dataclass(frozen=True, slots=True)
class DangerousToolSpec:
    name: str
    category: str
    permission: str
    method: DangerousMutationMethod
    endpoint_template: str
    revalidation_endpoint_template: str
    payload_fields: frozenset[str] = dataclass_field(default_factory=_empty_payload_fields)
    required_payload_fields: frozenset[str] = dataclass_field(default_factory=_empty_payload_fields)
    payload_defaults: dict[str, object] = dataclass_field(default_factory=_empty_payload_defaults)
    data_loss_possible: bool = True
    network_disruption_possible: bool = False
    quorum_risk: bool = False
    rollback_available: bool = False
    rollback_suggestions: tuple[str, ...] = dataclass_field(default_factory=_empty_suggestions)


def _spec(
    name: str,
    category: str,
    permission: str,
    method: DangerousMutationMethod,
    endpoint_template: str,
    revalidation_endpoint_template: str,
    *,
    payload_fields: frozenset[str] | None = None,
    required_payload_fields: frozenset[str] | None = None,
    payload_defaults: dict[str, object] | None = None,
    data_loss_possible: bool = True,
    network_disruption_possible: bool = False,
    quorum_risk: bool = False,
    rollback_available: bool = False,
    rollback_suggestions: tuple[str, ...] = (),
) -> DangerousToolSpec:
    return DangerousToolSpec(
        name=name,
        category=category,
        permission=permission,
        method=method,
        endpoint_template=endpoint_template,
        revalidation_endpoint_template=revalidation_endpoint_template,
        payload_fields=_empty_payload_fields() if payload_fields is None else payload_fields,
        required_payload_fields=_empty_payload_fields()
        if required_payload_fields is None
        else required_payload_fields,
        payload_defaults=_empty_payload_defaults()
        if payload_defaults is None
        else payload_defaults,
        data_loss_possible=data_loss_possible,
        network_disruption_possible=network_disruption_possible,
        quorum_risk=quorum_risk,
        rollback_available=rollback_available,
        rollback_suggestions=rollback_suggestions,
    )


DANGEROUS_TOOL_SPECS: tuple[DangerousToolSpec, ...] = (
    _spec(
        "delete_vm",
        "vm",
        "vm.lifecycle.destroy",
        "DELETE",
        "/nodes/{node}/qemu/{vmid}",
        "/nodes/{node}/qemu/{vmid}/status/current",
        rollback_suggestions=("Restore from a verified backup if deletion was unintended.",),
    ),
    _spec(
        "delete_lxc",
        "lxc",
        "lxc.lifecycle.destroy",
        "DELETE",
        "/nodes/{node}/lxc/{vmid}",
        "/nodes/{node}/lxc/{vmid}/status/current",
        rollback_suggestions=("Restore from a verified backup if deletion was unintended.",),
    ),
    _spec(
        "delete_vm_snapshot",
        "vm",
        "vm.snapshot.delete",
        "DELETE",
        "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}",
        "/nodes/{node}/qemu/{vmid}/snapshot",
        payload_fields=frozenset({"snapname"}),
        required_payload_fields=frozenset({"snapname"}),
        rollback_suggestions=("Snapshot deletion cannot be rolled back directly.",),
    ),
    _spec(
        "delete_lxc_snapshot",
        "lxc",
        "lxc.snapshot.delete",
        "DELETE",
        "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}",
        "/nodes/{node}/lxc/{vmid}/snapshot",
        payload_fields=frozenset({"snapname"}),
        required_payload_fields=frozenset({"snapname"}),
        rollback_suggestions=("Snapshot deletion cannot be rolled back directly.",),
    ),
    _spec(
        "rollback_vm_snapshot",
        "vm",
        "vm.snapshot.rollback",
        "POST",
        "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback",
        "/nodes/{node}/qemu/{vmid}/snapshot",
        payload_fields=frozenset({"snapname"}),
        required_payload_fields=frozenset({"snapname"}),
        rollback_available=True,
        rollback_suggestions=(
            "Take a fresh backup before rollback; rollback changes active VM state.",
        ),
    ),
    _spec(
        "rollback_lxc_snapshot",
        "lxc",
        "lxc.snapshot.rollback",
        "POST",
        "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback",
        "/nodes/{node}/lxc/{vmid}/snapshot",
        payload_fields=frozenset({"snapname"}),
        required_payload_fields=frozenset({"snapname"}),
        rollback_available=True,
        rollback_suggestions=(
            "Take a fresh backup before rollback; rollback changes active LXC state.",
        ),
    ),
    _spec(
        "node_reboot",
        "node",
        "node.power.reboot",
        "POST",
        "/nodes/{node}/status",
        "/nodes/{node}/status",
        payload_defaults={"command": "reboot"},
        data_loss_possible=False,
        network_disruption_possible=True,
        quorum_risk=True,
        rollback_suggestions=(
            "Wait for node recovery and migrate workloads if the node fails to return.",
        ),
    ),
    _spec(
        "node_shutdown",
        "node",
        "node.power.shutdown",
        "POST",
        "/nodes/{node}/status",
        "/nodes/{node}/status",
        payload_defaults={"command": "shutdown"},
        data_loss_possible=False,
        network_disruption_possible=True,
        quorum_risk=True,
        rollback_suggestions=("Power the node back on out of band if shutdown was unintended.",),
    ),
    _spec(
        "delete_storage",
        "storage",
        "storage.config.delete",
        "DELETE",
        "/storage/{storage_id}",
        "/storage/{storage_id}",
        rollback_suggestions=("Recreate storage configuration from version-controlled inventory.",),
    ),
    _spec(
        "delete_volume",
        "storage",
        "storage.volume.delete",
        "DELETE",
        "/nodes/{node}/storage/{storage_id}/content/{volume}",
        "/nodes/{node}/storage/{storage_id}/content/{volume}",
        payload_fields=frozenset({"volume"}),
        required_payload_fields=frozenset({"volume"}),
        rollback_suggestions=("Restore the deleted volume from backup if available.",),
    ),
    _spec(
        "apply_network_config",
        "network",
        "network.config.apply",
        "PUT",
        "/nodes/{node}/network",
        "/nodes/{node}/network",
        data_loss_possible=False,
        network_disruption_possible=True,
        rollback_available=True,
        rollback_suggestions=(
            "Use console access to revert networking if the node becomes unreachable.",
        ),
    ),
    _spec(
        "disable_firewall",
        "firewall",
        "firewall.config.write",
        "PUT",
        "/cluster/firewall/options",
        "/cluster/firewall/options",
        payload_defaults={"enable": 0},
        data_loss_possible=False,
        network_disruption_possible=True,
        rollback_available=True,
        rollback_suggestions=("Re-enable the firewall after validating emergency access.",),
    ),
    _spec(
        "delete_ceph_pool",
        "ceph",
        "ceph.pool.delete",
        "DELETE",
        "/nodes/{node}/ceph/pools/{pool}",
        "/nodes/{node}/ceph/pools",
        payload_fields=frozenset({"pool"}),
        required_payload_fields=frozenset({"pool"}),
        rollback_suggestions=(
            "Restore affected data from backup or replicas outside the deleted pool.",
        ),
    ),
    _spec(
        "remove_ceph_osd",
        "ceph",
        "ceph.osd.remove",
        "DELETE",
        "/nodes/{node}/ceph/osd/{osd_id}",
        "/nodes/{node}/ceph/osd",
        payload_fields=frozenset({"osd_id"}),
        required_payload_fields=frozenset({"osd_id"}),
        quorum_risk=True,
        rollback_suggestions=(
            "Recreate the OSD only after confirming cluster health and data safety.",
        ),
    ),
    _spec(
        "delete_user",
        "user",
        "user.delete",
        "DELETE",
        "/access/users/{userid}",
        "/access/users",
        payload_fields=frozenset({"userid"}),
        required_payload_fields=frozenset({"userid"}),
        data_loss_possible=False,
        rollback_available=True,
        rollback_suggestions=("Recreate the user and restore group/ACL assignments if needed.",),
    ),
)


def register_dangerous_tools(registry: ToolRegistry) -> None:
    for spec in DANGEROUS_TOOL_SPECS:
        registry.register(
            ToolDefinition(
                name=spec.name,
                category=spec.category,
                permission=spec.permission,
                risk="critical",
                dry_run=True,
                approval_default=True,
                connector="proxmox_api",
                handler=_build_dangerous_handler(spec),
                parameters_model=_parameters_model_for(spec),
                result_model=DangerousMutationResult,
            )
        )


def _build_dangerous_handler(
    spec: DangerousToolSpec,
) -> Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]:
    async def handler(request: ToolRequest, context: ToolExecutionContext) -> object:
        endpoint = _format_endpoint(spec.endpoint_template, request)
        revalidation_endpoint = _format_endpoint(spec.revalidation_endpoint_template, request)
        payload = _payload_for(spec, request)
        impact = _impact_for(spec, request)
        if request.options.dry_run:
            return _result(
                spec,
                request,
                endpoint,
                payload,
                impact,
                target_revalidated=False,
                revalidation_endpoint=revalidation_endpoint,
                result=None,
            )

        if context.proxmox_client is None:
            raise ToolExecutionError(
                error_code="PROXMOX_API_ERROR",
                message="Proxmox API client is not configured",
                retryable=False,
            )

        target_revalidated = False
        if context.settings.dangerous_operations.require_target_revalidation:
            try:
                await context.proxmox_client.get(revalidation_endpoint)
            except ProxmoxApiError as exc:
                raise ToolExecutionError(
                    error_code=exc.error_code,
                    message="Dangerous operation target revalidation failed",
                    details=exc.details,
                    retryable=exc.retryable,
                ) from exc
            target_revalidated = True

        try:
            if spec.method == "DELETE":
                data = await context.proxmox_client.delete(endpoint, data=payload)
            elif spec.method == "POST":
                data = await context.proxmox_client.post(endpoint, data=payload)
            else:
                data = await context.proxmox_client.put(endpoint, data=payload)
        except ProxmoxApiError as exc:
            raise ToolExecutionError(
                error_code=exc.error_code,
                message="Proxmox API request failed",
                details=exc.details,
                retryable=exc.retryable,
            ) from exc

        context.audit_metadata.update(
            {
                "target_revalidated": target_revalidated,
                "revalidation_endpoint": revalidation_endpoint,
            }
        )
        return _result(
            spec,
            request,
            endpoint,
            payload,
            impact,
            target_revalidated=target_revalidated,
            revalidation_endpoint=revalidation_endpoint,
            result=data,
        )

    return handler


def _payload_for(spec: DangerousToolSpec, request: ToolRequest) -> dict[str, object]:
    payload = dict(spec.payload_defaults)
    unsupported = set(request.parameters) - spec.payload_fields
    if unsupported:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Unsupported dangerous operation parameters: {', '.join(sorted(unsupported))}",
        )

    for field in spec.required_payload_fields:
        if field not in request.parameters:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message=f"Missing required dangerous operation parameter: {field}",
            )

    for field in spec.payload_fields:
        if field in request.parameters:
            value = request.parameters[field]
            if value is None:
                continue
            if not isinstance(value, str | int | bool):
                raise ToolExecutionError(
                    error_code="INVALID_REQUEST",
                    message=f"Dangerous operation parameter {field!r} must be scalar",
                )
            payload[field] = value

    return payload


def _format_endpoint(template: str, request: ToolRequest) -> str:
    values = {field: _path_value_for(field, request) for field in _template_fields(template)}
    for field, value in values.items():
        if value is None:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message=f"Missing required Proxmox path value: {field}",
            )
        _validate_path_segment(field, value)
    return template.format(**values)


def _path_value_for(field: str, request: ToolRequest) -> str | None:
    target_value = _target_path_value_for(field, request)
    parameter_value = request.parameters.get(field)
    if parameter_value is not None:
        parameter_text = str(parameter_value)
        if target_value is None:
            return parameter_text
        if parameter_text != target_value:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message=f"Parameter {field!r} conflicts with authorized target",
            )

    return target_value


def _target_path_value_for(field: str, request: ToolRequest) -> str | None:
    if field == "node":
        return request.target.node
    if field == "vmid":
        if request.target.vmid is not None:
            if (
                request.target.resource_id.isdigit()
                and int(request.target.resource_id) != request.target.vmid
            ):
                raise ToolExecutionError(
                    error_code="INVALID_REQUEST",
                    message="target.vmid conflicts with target.resource_id",
                )
            return str(request.target.vmid)
        if request.target.resource_type in {"vm", "lxc"}:
            return request.target.resource_id
    if field == "storage_id":
        if request.target.storage_id is not None:
            if (
                request.target.resource_type == "storage"
                and request.target.resource_id != request.target.storage_id
            ):
                raise ToolExecutionError(
                    error_code="INVALID_REQUEST",
                    message="target.storage_id conflicts with target.resource_id",
                )
            return request.target.storage_id
        if request.target.resource_type == "storage":
            return request.target.resource_id
    return None


def _template_fields(template: str) -> tuple[str, ...]:
    return tuple(
        field_name for _, field_name, _, _ in Formatter().parse(template) if field_name is not None
    )


def _validate_path_segment(field: str, value: str) -> None:
    if not _SAFE_SEGMENT.fullmatch(value):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Unsafe Proxmox path value for {field}",
        )


def _impact_for(spec: DangerousToolSpec, request: ToolRequest) -> dict[str, object]:
    return {
        "affected_resources": [
            {
                "type": request.target.resource_type,
                "id": request.target.resource_id,
                "node": request.target.node,
            }
        ],
        "estimated_downtime_seconds": None,
        "data_loss_possible": spec.data_loss_possible,
        "network_disruption_possible": spec.network_disruption_possible,
        "quorum_risk": spec.quorum_risk,
        "rollback_available": spec.rollback_available,
        "rollback_suggestions": list(spec.rollback_suggestions),
    }


def _result(
    spec: DangerousToolSpec,
    request: ToolRequest,
    endpoint: str,
    payload: dict[str, object],
    impact: dict[str, object],
    *,
    target_revalidated: bool,
    revalidation_endpoint: str,
    result: object | None,
) -> dict[str, object]:
    _ = request
    return {
        "dry_run": request.options.dry_run,
        "operation": spec.permission,
        "method": spec.method,
        "endpoint": endpoint,
        "payload": payload,
        "impact": impact,
        "target_revalidated": target_revalidated,
        "revalidation_endpoint": revalidation_endpoint,
        "result": result,
    }


def _parameters_model_for(spec: DangerousToolSpec) -> type[BaseModel]:
    fields: dict[str, tuple[type[object], object]] = {}
    for field in sorted(spec.payload_fields | frozenset(_template_fields(spec.endpoint_template))):
        default: object = ... if field in spec.required_payload_fields else None
        fields[field] = (object, default)

    model_name = "".join(part.capitalize() for part in spec.name.split("_")) + "Parameters"
    return create_model(
        model_name,
        __config__=ConfigDict(extra="forbid"),
        **cast(dict[str, Any], fields),
    )
