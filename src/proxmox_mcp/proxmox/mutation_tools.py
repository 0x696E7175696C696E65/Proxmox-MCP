from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from string import Formatter
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, create_model

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.reliability import request_fingerprint
from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolExecutionError, ToolRegistry

MutationMethod = Literal["POST", "PUT"]
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_.:@!+-]+$")
_SAFE_VM_CONFIG_FIELDS = frozenset({"name", "description", "tags", "onboot", "cores", "memory"})
_SAFE_LXC_CONFIG_FIELDS = frozenset(
    {"hostname", "description", "tags", "onboot", "cores", "memory"}
)


class MutationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool
    operation: str
    method: MutationMethod
    endpoint: str
    payload: dict[str, object]
    impact: dict[str, object]
    result: object | None = None
    task_ref: str | None = None


def _empty_payload_fields() -> frozenset[str]:
    return frozenset()


def _empty_suggestions() -> tuple[str, ...]:
    return ()


@dataclass(frozen=True, slots=True)
class MutationToolSpec:
    name: str
    category: str
    permission: str
    method: MutationMethod
    endpoint_template: str
    risk: Literal["low", "medium", "high", "critical"] = "medium"
    payload_fields: frozenset[str] = dataclass_field(default_factory=_empty_payload_fields)
    required_payload_fields: frozenset[str] = dataclass_field(default_factory=_empty_payload_fields)
    include_target_vmid: bool = False
    rollback_available: bool = False
    rollback_suggestions: tuple[str, ...] = dataclass_field(default_factory=_empty_suggestions)
    downtime_seconds: int | None = None


def _spec(
    name: str,
    category: str,
    permission: str,
    method: MutationMethod,
    endpoint_template: str,
    *,
    risk: Literal["low", "medium", "high", "critical"] = "medium",
    payload_fields: frozenset[str] | None = None,
    required_payload_fields: frozenset[str] | None = None,
    include_target_vmid: bool = False,
    rollback_available: bool = False,
    rollback_suggestions: tuple[str, ...] = (),
    downtime_seconds: int | None = None,
) -> MutationToolSpec:
    return MutationToolSpec(
        name=name,
        category=category,
        permission=permission,
        method=method,
        endpoint_template=endpoint_template,
        risk=risk,
        payload_fields=_empty_payload_fields() if payload_fields is None else payload_fields,
        required_payload_fields=_empty_payload_fields()
        if required_payload_fields is None
        else required_payload_fields,
        include_target_vmid=include_target_vmid,
        rollback_available=rollback_available,
        rollback_suggestions=rollback_suggestions,
        downtime_seconds=downtime_seconds,
    )


SAFE_MUTATION_TOOL_SPECS: tuple[MutationToolSpec, ...] = (
    _spec("start_vm", "vm", "vm.lifecycle.start", "POST", "/nodes/{node}/qemu/{vmid}/status/start"),
    _spec(
        "shutdown_vm",
        "vm",
        "vm.lifecycle.shutdown",
        "POST",
        "/nodes/{node}/qemu/{vmid}/status/shutdown",
        downtime_seconds=60,
    ),
    _spec(
        "reboot_vm",
        "vm",
        "vm.lifecycle.reboot",
        "POST",
        "/nodes/{node}/qemu/{vmid}/status/reboot",
        downtime_seconds=60,
    ),
    _spec(
        "stop_vm",
        "vm",
        "vm.lifecycle.stop",
        "POST",
        "/nodes/{node}/qemu/{vmid}/status/stop",
        risk="high",
        downtime_seconds=60,
    ),
    _spec(
        "start_lxc", "lxc", "lxc.lifecycle.start", "POST", "/nodes/{node}/lxc/{vmid}/status/start"
    ),
    _spec(
        "shutdown_lxc",
        "lxc",
        "lxc.lifecycle.shutdown",
        "POST",
        "/nodes/{node}/lxc/{vmid}/status/shutdown",
        downtime_seconds=60,
    ),
    _spec(
        "reboot_lxc",
        "lxc",
        "lxc.lifecycle.reboot",
        "POST",
        "/nodes/{node}/lxc/{vmid}/status/reboot",
        downtime_seconds=60,
    ),
    _spec(
        "stop_lxc",
        "lxc",
        "lxc.lifecycle.stop",
        "POST",
        "/nodes/{node}/lxc/{vmid}/status/stop",
        risk="high",
        downtime_seconds=60,
    ),
    _spec(
        "create_vm_snapshot",
        "vm",
        "vm.snapshot.create",
        "POST",
        "/nodes/{node}/qemu/{vmid}/snapshot",
        payload_fields=frozenset({"snapname", "description"}),
        required_payload_fields=frozenset({"snapname"}),
        rollback_available=True,
        rollback_suggestions=("Delete the created snapshot if validation fails.",),
    ),
    _spec(
        "create_lxc_snapshot",
        "lxc",
        "lxc.snapshot.create",
        "POST",
        "/nodes/{node}/lxc/{vmid}/snapshot",
        payload_fields=frozenset({"snapname", "description"}),
        required_payload_fields=frozenset({"snapname"}),
        rollback_available=True,
        rollback_suggestions=("Delete the created snapshot if validation fails.",),
    ),
    _spec(
        "run_vm_backup",
        "backup",
        "backup.run",
        "POST",
        "/nodes/{node}/vzdump",
        payload_fields=frozenset({"storage", "mode", "compress", "remove"}),
        required_payload_fields=frozenset({"storage", "mode"}),
        include_target_vmid=True,
        rollback_available=True,
        rollback_suggestions=(
            "Use the completed backup as a restore point if follow-up validation fails.",
        ),
    ),
    _spec(
        "update_vm_config",
        "vm",
        "vm.config.update",
        "PUT",
        "/nodes/{node}/qemu/{vmid}/config",
        payload_fields=frozenset({"config"}),
        required_payload_fields=frozenset({"config"}),
        rollback_available=True,
        rollback_suggestions=(
            "Review previous configuration and apply a compensating update if needed.",
        ),
    ),
    _spec(
        "update_lxc_config",
        "lxc",
        "lxc.config.update",
        "PUT",
        "/nodes/{node}/lxc/{vmid}/config",
        payload_fields=frozenset({"config"}),
        required_payload_fields=frozenset({"config"}),
        rollback_available=True,
        rollback_suggestions=(
            "Review previous configuration and apply a compensating update if needed.",
        ),
    ),
)


def register_safe_mutation_tools(registry: ToolRegistry) -> None:
    for spec in SAFE_MUTATION_TOOL_SPECS:
        registry.register(
            ToolDefinition(
                name=spec.name,
                category=spec.category,
                permission=spec.permission,
                risk=spec.risk,
                dry_run=True,
                approval_default=spec.downtime_seconds is not None,
                connector="proxmox_api",
                handler=_build_mutation_handler(spec),
                parameters_model=_parameters_model_for(spec),
                result_model=MutationResult,
            )
        )


def _build_mutation_handler(
    spec: MutationToolSpec,
) -> Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]:
    async def handler(request: ToolRequest, context: ToolExecutionContext) -> object:
        path = _format_endpoint(spec, request)
        payload = _payload_for(spec, request)
        impact = _impact_for(spec, request)
        if request.options.dry_run:
            return _result(spec, request, path, payload, impact, result=None)

        if context.proxmox_client is None:
            raise ToolExecutionError(
                error_code="PROXMOX_API_ERROR",
                message="Proxmox API client is not configured",
                retryable=False,
            )

        try:
            if spec.method == "POST":
                data = await context.proxmox_client.post(path, data=payload)
            else:
                data = await context.proxmox_client.put(path, data=payload)
        except ProxmoxApiError as exc:
            raise ToolExecutionError(
                error_code=exc.error_code,
                message="Proxmox API request failed",
                details=exc.details,
                retryable=exc.retryable,
            ) from exc

        task_ref = await _record_proxmox_task(
            spec,
            request,
            context,
            path=path,
            payload=payload,
            result=data,
        )
        return _result(spec, request, path, payload, impact, result=data, task_ref=task_ref)

    return handler


def _result(
    spec: MutationToolSpec,
    request: ToolRequest,
    path: str,
    payload: dict[str, object],
    impact: dict[str, object],
    *,
    result: object | None,
    task_ref: str | None = None,
) -> dict[str, object]:
    return {
        "dry_run": request.options.dry_run,
        "operation": spec.name,
        "method": spec.method,
        "endpoint": path,
        "payload": payload,
        "impact": impact,
        "result": result,
        "task_ref": task_ref,
    }


async def _record_proxmox_task(
    spec: MutationToolSpec,
    request: ToolRequest,
    context: ToolExecutionContext,
    *,
    path: str,
    payload: dict[str, object],
    result: object,
) -> str | None:
    if context.proxmox_task_store is None or not _is_upid(result):
        return None
    fingerprint = request_fingerprint(
        {
            "tool": spec.name,
            "target": request.target.model_dump(mode="json"),
            "parameters": request.parameters,
            "payload": payload,
        }
    )
    task = await context.proxmox_task_store.record_task(
        upid=str(result),
        operation=spec.name,
        method=spec.method,
        endpoint=path,
        target=cast(dict[str, object], request.target.model_dump(mode="json")),
        request_fingerprint=fingerprint,
        idempotency_key=request.options.idempotency_key,
    )
    context.audit_metadata["proxmox_task_id"] = task.task_id
    context.audit_metadata["proxmox_task_upid"] = task.upid
    return task.task_id


def _is_upid(result: object) -> bool:
    return isinstance(result, str) and result.startswith("UPID:")


def _format_endpoint(spec: MutationToolSpec, request: ToolRequest) -> str:
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

    if target_value is None and parameter_value is not None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Target field is required for Proxmox path value: {field}",
        )

    return target_value


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

    return None


def _payload_for(spec: MutationToolSpec, request: ToolRequest) -> dict[str, object]:
    path_fields = set(_template_fields(spec.endpoint_template))
    payload: dict[str, object] = {}
    for key, value in request.parameters.items():
        if key in path_fields:
            continue
        if key not in spec.payload_fields:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message=f"Unsupported Proxmox mutation parameter: {key}",
            )
        if key == "config" and not isinstance(value, dict):
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message="Config updates require an object payload",
            )
        if key == "config":
            payload.update(_safe_config_payload_for(spec, cast(dict[str, object], value)))
        else:
            payload[key] = value

    missing = [field for field in spec.required_payload_fields if field not in request.parameters]
    if missing:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Missing required Proxmox mutation parameter: {missing[0]}",
        )

    if spec.include_target_vmid:
        payload["vmid"] = _path_value_for("vmid", request)

    return payload


def _safe_config_payload_for(spec: MutationToolSpec, value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Config updates require an object payload",
        )

    config = cast(dict[str, object], value)
    allowed = _SAFE_LXC_CONFIG_FIELDS if spec.category == "lxc" else _SAFE_VM_CONFIG_FIELDS
    unsafe = sorted(key for key in config if key not in allowed)
    if unsafe:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"Unsupported safe config field: {unsafe[0]}",
        )

    return dict(config)


def _impact_for(spec: MutationToolSpec, request: ToolRequest) -> dict[str, object]:
    return {
        "affected_resources": [
            {
                "type": request.target.resource_type,
                "id": request.target.resource_id,
                "node": request.target.node,
            }
        ],
        "estimated_downtime_seconds": spec.downtime_seconds,
        "data_loss_possible": False,
        "rollback_available": spec.rollback_available,
        "rollback_suggestions": _rollback_suggestions_for(spec),
    }


def _rollback_suggestions_for(spec: MutationToolSpec) -> list[str]:
    return list(spec.rollback_suggestions)


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


def _parameters_model_for(spec: MutationToolSpec) -> type[BaseModel]:
    field_names = sorted(set(_template_fields(spec.endpoint_template)) | spec.payload_fields)
    fields = {
        name: (_field_type_for(name), ... if name in spec.required_payload_fields else None)
        for name in field_names
    }
    return create_model(
        f"{_pascal_case(spec.name)}Parameters",
        __config__=ConfigDict(extra="forbid"),
        **cast(dict[str, Any], fields),
    )


def _field_type_for(name: str) -> object:
    if name == "vmid":
        return int | None
    if name == "config":
        return dict[str, object] | None
    if name == "remove":
        return bool | None
    return str | None


def _pascal_case(value: str) -> str:
    return "".join(part.capitalize() for part in value.split("_"))
