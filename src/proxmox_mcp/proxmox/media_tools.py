from __future__ import annotations

import re
from typing import Literal
from urllib.parse import quote, urlparse

from pydantic import BaseModel, ConfigDict, Field

from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolExecutionError, ToolRegistry

_SAFE_MEDIA_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+@-]{0,180}$")
_SAFE_DEVICE = re.compile(r"^(ide|sata|scsi|virtio)\d+$")


class EmptyMediaParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DownloadIsoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1)
    filename: str = Field(min_length=1)
    checksum: str | None = None
    checksum_algorithm: Literal["md5", "sha1", "sha224", "sha256", "sha384", "sha512"] | None = None


class TemplateDownloadParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    template: str = Field(min_length=1)


class VmIsoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1)
    device: str = "ide2"


class PrepareVmInstallMediaParameters(DownloadIsoParameters):
    device: str = "ide2"


class CreateVmFromIsoParameters(PrepareVmInstallMediaParameters):
    vmid: int | None = Field(default=None, ge=1)
    name: str | None = Field(default=None, min_length=1)
    cores: int = Field(default=2, ge=1, le=128)
    memory: int = Field(default=2048, ge=128)


class CreateLxcFromTemplateParameters(TemplateDownloadParameters):
    hostname: str = Field(min_length=1)
    password_secret_ref: str = Field(min_length=1)
    cores: int = Field(default=1, ge=1, le=128)
    memory: int = Field(default=512, ge=64)
    rootfs_size_gb: int = Field(default=8, ge=1)


class DeleteMediaParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1)


def register_media_tools(registry: ToolRegistry) -> None:
    registry.register(
        ToolDefinition(
            name="list_iso_images",
            description=(
                "Read-only: list ISO images available on a storage. Provide target.node and "
                "target.storage_id. Returns the storage content items; never mutates state."
            ),
            category="storage",
            permission="storage.iso.read",
            risk="low",
            dry_run=False,
            approval_default=False,
            connector="proxmox_api",
            parameters_model=EmptyMediaParameters,
            handler=_list_iso_images,
        )
    )
    registry.register(
        ToolDefinition(
            name="list_lxc_templates",
            description=(
                "Read-only: list LXC container templates (vztmpl) on a storage. Provide "
                "target.node and target.storage_id. Never mutates state."
            ),
            category="lxc",
            permission="lxc.template.read",
            risk="low",
            dry_run=False,
            approval_default=False,
            connector="proxmox_api",
            parameters_model=EmptyMediaParameters,
            handler=_list_lxc_templates,
        )
    )
    registry.register(
        ToolDefinition(
            name="download_iso_from_url",
            description=(
                "Medium-risk: instruct the Proxmox node to download an ISO from an https URL into "
                "a storage. Requires parameters.url and parameters.filename (must end in .iso); "
                "optional parameters.checksum + parameters.checksum_algorithm (supply both or "
                "neither). Dry-run by default; approval required. Target: node + storage_id."
            ),
            category="storage",
            permission="storage.iso.download",
            risk="medium",
            dry_run=True,
            approval_default=True,
            connector="proxmox_api",
            parameters_model=DownloadIsoParameters,
            handler=_download_iso_from_url,
        )
    )
    registry.register(
        ToolDefinition(
            name="download_lxc_template",
            description=(
                "Medium-risk: download an LXC template into a storage. Requires "
                "parameters.template (an aplinfo template name). Dry-run by default; approval "
                "required. Target: node + storage_id."
            ),
            category="lxc",
            permission="lxc.template.download",
            risk="medium",
            dry_run=True,
            approval_default=True,
            connector="proxmox_api",
            parameters_model=TemplateDownloadParameters,
            handler=_download_lxc_template,
        )
    )
    registry.register(
        ToolDefinition(
            name="attach_iso_to_vm",
            description=(
                "Medium-risk: attach an ISO as a CD-ROM drive to a VM. Requires "
                "parameters.filename (.iso); optional parameters.device (drive bay, default "
                "ide2). Dry-run by default. Target: node + vmid + storage_id."
            ),
            category="vm",
            permission="vm.media.attach",
            risk="medium",
            dry_run=True,
            approval_default=False,
            connector="proxmox_api",
            parameters_model=VmIsoParameters,
            handler=_attach_iso_to_vm,
        )
    )
    registry.register(
        ToolDefinition(
            name="detach_iso_from_vm",
            description=(
                "Medium-risk: eject the CD-ROM/ISO from a VM drive bay. Optional "
                "parameters.device selects the drive (default ide2). Dry-run by default. "
                "Target: node + vmid."
            ),
            category="vm",
            permission="vm.media.detach",
            risk="medium",
            dry_run=True,
            approval_default=False,
            connector="proxmox_api",
            parameters_model=VmIsoParameters,
            handler=_detach_iso_from_vm,
        )
    )
    registry.register(
        ToolDefinition(
            name="delete_iso_image",
            description=(
                "High-risk: delete an ISO image from a storage. Requires parameters.filename. "
                "Dry-run by default; approval required. Target: node + storage_id."
            ),
            category="storage",
            permission="storage.iso.delete",
            risk="high",
            dry_run=True,
            approval_default=True,
            connector="proxmox_api",
            parameters_model=DeleteMediaParameters,
            handler=_delete_iso_image,
        )
    )
    registry.register(
        ToolDefinition(
            name="delete_lxc_template",
            description=(
                "High-risk: delete an LXC template from a storage. Requires parameters.filename. "
                "Dry-run by default; approval required. Target: node + storage_id."
            ),
            category="lxc",
            permission="lxc.template.delete",
            risk="high",
            dry_run=True,
            approval_default=True,
            connector="proxmox_api",
            parameters_model=DeleteMediaParameters,
            handler=_delete_lxc_template,
        )
    )
    registry.register(
        ToolDefinition(
            name="prepare_vm_install_media",
            description=(
                "High-risk composite: download and stage install media so a VM can boot from it. "
                "Requires parameters.url and parameters.filename (.iso). Dry-run by default; "
                "approval required. Target: node + storage_id."
            ),
            category="vm",
            permission="vm.media.prepare",
            risk="high",
            dry_run=True,
            approval_default=True,
            connector="proxmox_api",
            parameters_model=PrepareVmInstallMediaParameters,
            handler=_prepare_vm_install_media,
        )
    )
    registry.register(
        ToolDefinition(
            name="create_vm_from_iso",
            description=(
                "High-risk composite: create a VM and attach an ISO to boot the installer. "
                "Requires parameters.url and parameters.filename (.iso); optional parameters "
                "vmid, name, cores, memory. Dry-run by default; approval required. "
                "Target: node + storage_id."
            ),
            category="vm",
            permission="vm.lifecycle.create",
            risk="high",
            dry_run=True,
            approval_default=True,
            connector="proxmox_api",
            parameters_model=CreateVmFromIsoParameters,
            handler=_create_vm_from_iso,
        )
    )
    registry.register(
        ToolDefinition(
            name="create_lxc_from_template",
            description=(
                "High-risk composite: create an LXC container from a template. Requires "
                "parameters.template, parameters.hostname, and parameters.password_secret_ref; "
                "optional cores, memory, rootfs_size_gb. A dry-run returns a plan; live execution "
                "is currently guarded (returns NOT_IMPLEMENTED) pending secret-resolution wiring. "
                "Target: node + storage_id."
            ),
            category="lxc",
            permission="lxc.lifecycle.create",
            risk="high",
            dry_run=True,
            approval_default=True,
            connector="proxmox_api",
            parameters_model=CreateLxcFromTemplateParameters,
            handler=_create_lxc_from_template,
        )
    )


async def _list_iso_images(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    return await _list_storage_content(request, context, content_type="iso")


async def _list_lxc_templates(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    return await _list_storage_content(request, context, content_type="vztmpl")


async def _download_iso_from_url(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = DownloadIsoParameters.model_validate(request.parameters)
    storage = _storage_id(request)
    node = _node(request)
    _validate_https_url(parameters.url)
    _validate_media_filename(parameters.filename, expected_suffix=".iso")
    if (parameters.checksum is None) != (parameters.checksum_algorithm is None):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="checksum and checksum_algorithm must be provided together",
            retryable=False,
        )
    endpoint = f"/nodes/{node}/storage/{storage}/download-url"
    payload: dict[str, object] = {
        "content": "iso",
        "filename": parameters.filename,
        "url": parameters.url,
    }
    if parameters.checksum is not None and parameters.checksum_algorithm is not None:
        payload["checksum"] = parameters.checksum
        payload["checksum-algorithm"] = parameters.checksum_algorithm
    return await _post_or_preview(
        request,
        context,
        operation="download_iso_from_url",
        endpoint=endpoint,
        payload=payload,
        impact={
            "storage_id": storage,
            "content": "iso",
            "network_fetch": True,
            "mutation": "download_storage_content",
        },
    )


async def _download_lxc_template(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = TemplateDownloadParameters.model_validate(request.parameters)
    storage = _storage_id(request)
    node = _node(request)
    _validate_media_filename(parameters.template)
    endpoint = f"/nodes/{node}/aplinfo"
    payload: dict[str, object] = {"storage": storage, "template": parameters.template}
    return await _post_or_preview(
        request,
        context,
        operation="download_lxc_template",
        endpoint=endpoint,
        payload=payload,
        impact={
            "storage_id": storage,
            "content": "vztmpl",
            "mutation": "download_lxc_template",
        },
    )


async def _attach_iso_to_vm(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = VmIsoParameters.model_validate(request.parameters)
    storage = _storage_id(request)
    node = _node(request)
    vmid = _vmid(request)
    _validate_media_filename(parameters.filename, expected_suffix=".iso")
    _validate_device(parameters.device)
    endpoint = f"/nodes/{node}/qemu/{vmid}/config"
    payload: dict[str, object] = {
        parameters.device: f"{storage}:iso/{parameters.filename},media=cdrom"
    }
    return await _put_or_preview(
        request,
        context,
        operation="attach_iso_to_vm",
        endpoint=endpoint,
        payload=payload,
        impact={"vmid": vmid, "device": parameters.device, "mutation": "attach_iso"},
    )


async def _detach_iso_from_vm(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = VmIsoParameters.model_validate(request.parameters)
    node = _node(request)
    vmid = _vmid(request)
    _validate_device(parameters.device)
    endpoint = f"/nodes/{node}/qemu/{vmid}/config"
    payload: dict[str, object] = {parameters.device: "none,media=cdrom"}
    return await _put_or_preview(
        request,
        context,
        operation="detach_iso_from_vm",
        endpoint=endpoint,
        payload=payload,
        impact={"vmid": vmid, "device": parameters.device, "mutation": "detach_iso"},
    )


async def _delete_iso_image(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = DeleteMediaParameters.model_validate(request.parameters)
    _validate_media_filename(parameters.filename, expected_suffix=".iso")
    return await _delete_storage_content(
        request,
        context,
        operation="delete_iso_image",
        content_path=f"iso/{parameters.filename}",
        content_type="iso",
    )


async def _delete_lxc_template(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = DeleteMediaParameters.model_validate(request.parameters)
    _validate_media_filename(parameters.filename)
    return await _delete_storage_content(
        request,
        context,
        operation="delete_lxc_template",
        content_path=f"vztmpl/{parameters.filename}",
        content_type="vztmpl",
    )


async def _prepare_vm_install_media(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = PrepareVmInstallMediaParameters.model_validate(request.parameters)
    storage = _storage_id(request)
    node = _node(request)
    vmid = _vmid(request)
    _validate_https_url(parameters.url)
    _validate_media_filename(parameters.filename, expected_suffix=".iso")
    _validate_device(parameters.device)
    download_endpoint = f"/nodes/{node}/storage/{storage}/download-url"
    attach_endpoint = f"/nodes/{node}/qemu/{vmid}/config"
    download_payload = _iso_download_payload(parameters)
    attach_payload: dict[str, object] = {
        parameters.device: f"{storage}:iso/{parameters.filename},media=cdrom"
    }
    if not request.options.dry_run:
        try:
            await _client(context).post(download_endpoint, data=download_payload)
            await _client(context).put(attach_endpoint, data=attach_payload)
        except ProxmoxApiError as exc:
            raise _tool_error_from_proxmox(exc) from exc
    return {
        "dry_run": request.options.dry_run,
        "operation": "prepare_vm_install_media",
        "mutation_performed": not request.options.dry_run,
        "steps": [
            {
                "tool": "download_iso_from_url",
                "endpoint": download_endpoint,
                "payload": download_payload,
            },
            {
                "tool": "attach_iso_to_vm",
                "endpoint": attach_endpoint,
                "payload": attach_payload,
            },
        ],
    }


async def _create_vm_from_iso(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = CreateVmFromIsoParameters.model_validate(request.parameters)
    storage = _storage_id(request)
    node = _node(request)
    vmid = parameters.vmid or _vmid(request)
    _validate_https_url(parameters.url)
    _validate_media_filename(parameters.filename, expected_suffix=".iso")
    _validate_device(parameters.device)
    if parameters.name is not None:
        _validate_media_filename(parameters.name)
    download_endpoint = f"/nodes/{node}/storage/{storage}/download-url"
    create_endpoint = f"/nodes/{node}/qemu"
    attach_endpoint = f"/nodes/{node}/qemu/{vmid}/config"
    download_payload = _iso_download_payload(parameters)
    create_payload: dict[str, object] = {
        "vmid": vmid,
        "cores": parameters.cores,
        "memory": parameters.memory,
    }
    if parameters.name is not None:
        create_payload["name"] = parameters.name
    attach_payload: dict[str, object] = {
        parameters.device: f"{storage}:iso/{parameters.filename},media=cdrom"
    }
    if not request.options.dry_run:
        try:
            await _client(context).post(download_endpoint, data=download_payload)
            await _client(context).post(create_endpoint, data=create_payload)
            await _client(context).put(attach_endpoint, data=attach_payload)
        except ProxmoxApiError as exc:
            raise _tool_error_from_proxmox(exc) from exc
    return {
        "dry_run": request.options.dry_run,
        "operation": "create_vm_from_iso",
        "mutation_performed": not request.options.dry_run,
        "steps": [
            {
                "tool": "download_iso_from_url",
                "endpoint": download_endpoint,
                "payload": download_payload,
            },
            {"tool": "create_vm", "endpoint": create_endpoint, "payload": create_payload},
            {"tool": "attach_iso_to_vm", "endpoint": attach_endpoint, "payload": attach_payload},
        ],
    }


async def _create_lxc_from_template(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = CreateLxcFromTemplateParameters.model_validate(request.parameters)
    storage = _storage_id(request)
    node = _node(request)
    vmid = _vmid(request)
    _validate_media_filename(parameters.template)
    _validate_media_filename(parameters.hostname)
    if not parameters.password_secret_ref.startswith("secret://"):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="password_secret_ref must be a secret:// reference",
            retryable=False,
        )
    if not request.options.dry_run:
        raise ToolExecutionError(
            error_code="NOT_IMPLEMENTED",
            message=(
                "create_lxc_from_template live execution requires secret resolution "
                "before a container password can be sent to Proxmox"
            ),
            retryable=False,
            details={
                "required_evidence": (
                    "secret-provider password resolution without echoing raw secrets"
                )
            },
        )
    template_endpoint = f"/nodes/{node}/aplinfo"
    create_endpoint = f"/nodes/{node}/lxc"
    template_payload: dict[str, object] = {"storage": storage, "template": parameters.template}
    create_payload: dict[str, object] = {
        "vmid": vmid,
        "hostname": parameters.hostname,
        "ostemplate": f"{storage}:vztmpl/{parameters.template}",
        "password": f"<secret-ref:{parameters.password_secret_ref}>",
        "cores": parameters.cores,
        "memory": parameters.memory,
        "rootfs": f"{storage}:{parameters.rootfs_size_gb}",
    }
    if not request.options.dry_run:
        try:
            await _client(context).post(template_endpoint, data=template_payload)
            await _client(context).post(create_endpoint, data=create_payload)
        except ProxmoxApiError as exc:
            raise _tool_error_from_proxmox(exc) from exc
    return {
        "dry_run": request.options.dry_run,
        "operation": "create_lxc_from_template",
        "mutation_performed": not request.options.dry_run,
        "steps": [
            {
                "tool": "download_lxc_template",
                "endpoint": template_endpoint,
                "payload": template_payload,
            },
            {"tool": "create_lxc", "endpoint": create_endpoint, "payload": create_payload},
        ],
    }


async def _list_storage_content(
    request: ToolRequest,
    context: ToolExecutionContext,
    *,
    content_type: Literal["iso", "vztmpl"],
) -> dict[str, object]:
    storage = _storage_id(request)
    node = _node(request)
    endpoint = f"/nodes/{node}/storage/{storage}/content"
    try:
        items = await _client(context).get(endpoint, params={"content": content_type})
    except ProxmoxApiError as exc:
        raise _tool_error_from_proxmox(exc) from exc
    if not isinstance(items, list):
        items = []
    return {
        "operation": f"list_{content_type}",
        "node": node,
        "storage_id": storage,
        "content_type": content_type,
        "items": items,
    }


def _iso_download_payload(parameters: DownloadIsoParameters) -> dict[str, object]:
    payload: dict[str, object] = {
        "content": "iso",
        "filename": parameters.filename,
        "url": parameters.url,
    }
    if parameters.checksum is not None and parameters.checksum_algorithm is not None:
        payload["checksum"] = parameters.checksum
        payload["checksum-algorithm"] = parameters.checksum_algorithm
    return payload


async def _post_or_preview(
    request: ToolRequest,
    context: ToolExecutionContext,
    *,
    operation: str,
    endpoint: str,
    payload: dict[str, object],
    impact: dict[str, object],
) -> dict[str, object]:
    result: object | None = None
    if not request.options.dry_run:
        try:
            result = await _client(context).post(endpoint, data=payload)
        except ProxmoxApiError as exc:
            raise _tool_error_from_proxmox(exc) from exc
    return _mutation_result(request, operation, "POST", endpoint, payload, impact, result)


async def _put_or_preview(
    request: ToolRequest,
    context: ToolExecutionContext,
    *,
    operation: str,
    endpoint: str,
    payload: dict[str, object],
    impact: dict[str, object],
) -> dict[str, object]:
    result: object | None = None
    if not request.options.dry_run:
        try:
            result = await _client(context).put(endpoint, data=payload)
        except ProxmoxApiError as exc:
            raise _tool_error_from_proxmox(exc) from exc
    return _mutation_result(request, operation, "PUT", endpoint, payload, impact, result)


async def _delete_storage_content(
    request: ToolRequest,
    context: ToolExecutionContext,
    *,
    operation: str,
    content_path: str,
    content_type: str,
) -> dict[str, object]:
    storage = _storage_id(request)
    node = _node(request)
    volid = f"{storage}:{content_path}"
    endpoint = f"/nodes/{node}/storage/{storage}/content/{quote(volid, safe='')}"
    payload: dict[str, object] = {"volume": volid}
    result: object | None = None
    if not request.options.dry_run:
        try:
            result = await _client(context).delete(endpoint)
        except ProxmoxApiError as exc:
            raise _tool_error_from_proxmox(exc) from exc
    return _mutation_result(
        request,
        operation,
        "DELETE",
        endpoint,
        payload,
        {"storage_id": storage, "content": content_type, "mutation": "delete_storage_content"},
        result,
    )


def _mutation_result(
    request: ToolRequest,
    operation: str,
    method: str,
    endpoint: str,
    payload: dict[str, object],
    impact: dict[str, object],
    result: object | None,
) -> dict[str, object]:
    return {
        "dry_run": request.options.dry_run,
        "operation": operation,
        "method": method,
        "endpoint": endpoint,
        "payload": payload,
        "impact": impact,
        "result": result,
    }


def _client(context: ToolExecutionContext):
    if context.proxmox_client is None:
        raise ToolExecutionError(
            error_code="PROXMOX_API_ERROR",
            message="Proxmox client is not configured",
            retryable=True,
        )
    return context.proxmox_client


def _node(request: ToolRequest) -> str:
    if request.target.node is None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Target node is required",
            retryable=False,
        )
    return request.target.node


def _storage_id(request: ToolRequest) -> str:
    if request.target.storage_id is None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Target storage_id is required",
            retryable=False,
        )
    _validate_media_filename(request.target.storage_id)
    return request.target.storage_id


def _vmid(request: ToolRequest) -> int:
    if request.target.vmid is None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Target vmid is required",
            retryable=False,
        )
    return request.target.vmid


def _validate_https_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="download URL must be an https URL without userinfo",
            retryable=False,
        )


def _validate_media_filename(value: str, *, expected_suffix: str | None = None) -> None:
    if "/" in value or "\\" in value or not _SAFE_MEDIA_NAME.fullmatch(value):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="media filename contains unsupported characters",
            retryable=False,
        )
    if expected_suffix is not None and not value.lower().endswith(expected_suffix):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message=f"media filename must end with {expected_suffix}",
            retryable=False,
        )


def _validate_device(value: str) -> None:
    if not _SAFE_DEVICE.fullmatch(value):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="VM media device must be a safe disk bus slot such as ide2 or sata0",
            retryable=False,
        )


def _tool_error_from_proxmox(exc: ProxmoxApiError) -> ToolExecutionError:
    return ToolExecutionError(
        error_code=exc.error_code,
        message=str(exc),
        retryable=exc.retryable,
        details=exc.details,
    )
