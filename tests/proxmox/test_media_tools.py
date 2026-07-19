from __future__ import annotations

from typing import cast

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import InMemoryProxmoxApiClient, register_media_tools
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import (
    ToolDefinition,
    ToolErrorResponse,
    ToolGuardDecision,
    ToolRegistry,
)


class AllowGuard:
    async def evaluate(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolGuardDecision:
        _ = definition, request, context
        return ToolGuardDecision.allowed()


def make_registry() -> ToolRegistry:
    registry = ToolRegistry(guard=AllowGuard())
    register_media_tools(registry)
    return registry


def make_request(
    *,
    resource_type: str = "storage",
    resource_id: str = "local",
    node: str = "pve-1",
    vmid: int | None = None,
    storage_id: str = "local",
    parameters: dict[str, object] | None = None,
    dry_run: bool = False,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            cluster="lab",
            node=node,
            resource_type=resource_type,
            resource_id=resource_id,
            vmid=vmid,
            storage_id=storage_id,
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


def make_context(
    request: ToolRequest,
    proxmox_client: InMemoryProxmoxApiClient,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        proxmox_client=proxmox_client,
    )


async def test_list_iso_images_reads_storage_content_iso_entries() -> None:
    registry = make_registry()
    client = InMemoryProxmoxApiClient(
        {
            "/nodes/pve-1/storage/local/content": [
                {"volid": "local:iso/debian.iso", "content": "iso", "size": 123}
            ]
        }
    )
    request = make_request()

    response = await registry.execute("list_iso_images", request, make_context(request, client))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["storage_id"] == "local"
    assert result["content_type"] == "iso"
    assert cast(list[object], result["items"])[0] == {
        "volid": "local:iso/debian.iso",
        "content": "iso",
        "size": 123,
    }
    assert client.requests[-1].params == {"content": "iso"}


async def test_detach_iso_from_vm_does_not_require_filename() -> None:
    registry = make_registry()
    request = make_request(
        resource_type="vm",
        resource_id="100",
        vmid=100,
        parameters={"device": "ide2"},
        dry_run=True,
    )

    response = await registry.execute(
        "detach_iso_from_vm", request, make_context(request, InMemoryProxmoxApiClient())
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["payload"] == {"ide2": "none,media=cdrom"}


async def test_detach_iso_from_vm_rejects_phantom_filename_parameter() -> None:
    registry = make_registry()
    request = make_request(
        resource_type="vm",
        resource_id="100",
        vmid=100,
        parameters={"device": "ide2", "filename": "debian.iso"},
        dry_run=True,
    )

    response = await registry.execute(
        "detach_iso_from_vm", request, make_context(request, InMemoryProxmoxApiClient())
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"


async def test_download_iso_from_url_dry_run_rejects_insecure_or_userinfo_urls() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "url": "https://user@example.test/debian.iso",
            "filename": "debian.iso",
        },
        dry_run=True,
    )

    response = await registry.execute(
        "download_iso_from_url",
        request,
        make_context(request, InMemoryProxmoxApiClient()),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "https URL without userinfo" in response.error.message


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest/meta-data/iam/",
        "https://127.0.0.1/debian.iso",
        "https://localhost/debian.iso",
        "https://10.0.0.5/debian.iso",
        "https://192.168.1.10/debian.iso",
        "https://[::1]/debian.iso",
        "https://pve.internal/debian.iso",
    ],
)
async def test_download_iso_from_url_rejects_ssrf_hosts(url: str) -> None:
    registry = make_registry()
    request = make_request(parameters={"url": url, "filename": "debian.iso"}, dry_run=True)

    response = await registry.execute(
        "download_iso_from_url",
        request,
        make_context(request, InMemoryProxmoxApiClient()),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"


async def test_download_lxc_template_live_uses_aplinfo_endpoint() -> None:
    registry = make_registry()
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/aplinfo": {"upid": "UPID:pve-1:1"}})
    request = make_request(
        parameters={"template": "debian-12-standard_12.7-1_amd64.tar.zst"},
        dry_run=False,
    )

    response = await registry.execute(
        "download_lxc_template", request, make_context(request, client)
    )

    assert isinstance(response, ToolResponse)
    api_request = client.requests[-1]
    assert api_request.method == "POST"
    assert api_request.path == "/nodes/pve-1/aplinfo"
    assert api_request.data == {
        "storage": "local",
        "template": "debian-12-standard_12.7-1_amd64.tar.zst",
    }


async def test_attach_iso_to_vm_dry_run_builds_cdrom_config_without_mutation() -> None:
    registry = make_registry()
    client = InMemoryProxmoxApiClient()
    request = make_request(
        resource_type="vm",
        resource_id="100",
        vmid=100,
        parameters={"filename": "debian.iso", "device": "ide2"},
        dry_run=True,
    )

    response = await registry.execute("attach_iso_to_vm", request, make_context(request, client))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["endpoint"] == "/nodes/pve-1/qemu/100/config"
    assert result["payload"] == {"ide2": "local:iso/debian.iso,media=cdrom"}
    assert client.requests == []
