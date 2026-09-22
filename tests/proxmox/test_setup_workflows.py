from __future__ import annotations

from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    InMemoryProxmoxApiClient,
    register_helper_script_tools,
    register_media_tools,
)
from proxmox_mcp.proxmox.helper_scripts import HelperScript, HelperScriptCatalog
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolGuardDecision, ToolRegistry


class AllowGuard:
    async def evaluate(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolGuardDecision:
        _ = definition, request, context
        return ToolGuardDecision.allowed()


class FakeCatalogResolver:
    async def load_catalog(self) -> HelperScriptCatalog:
        return HelperScriptCatalog(
            source_repo="https://github.com/community-scripts/ProxmoxVE",
            source_commit="primary-commit",
            fallback_used=False,
            scripts=(
                HelperScript(
                    script_id="ct/adguard.sh",
                    name="adguard",
                    category="ct",
                    path="ct/adguard.sh",
                    download_url=(
                        "https://raw.githubusercontent.com/"
                        "community-scripts/ProxmoxVE/primary-commit/ct/adguard.sh"
                    ),
                    blob_sha="blob-primary",
                    size=42,
                ),
            ),
        )

    async def fetch_script_content(
        self, script_id: str
    ) -> tuple[HelperScriptCatalog, HelperScript, str]:
        catalog = await self.load_catalog()
        script = catalog.scripts[0]
        assert script.script_id == script_id
        return catalog, script, "#!/usr/bin/env bash\necho ok\n"


def make_registry() -> ToolRegistry:
    registry = ToolRegistry(guard=AllowGuard())
    register_media_tools(registry)
    register_helper_script_tools(registry, catalog_resolver=FakeCatalogResolver())
    return registry


def make_request(
    *,
    resource_type: str = "vm",
    resource_id: str = "100",
    node: str = "pve-1",
    vmid: int | None = 100,
    storage_id: str = "local",
    parameters: dict[str, object] | None = None,
    dry_run: bool = True,
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
    proxmox_client: InMemoryProxmoxApiClient | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        proxmox_client=proxmox_client,
    )


async def test_prepare_vm_install_media_dry_run_plans_iso_download_and_attach() -> None:
    registry = make_registry()
    request = make_request(
        parameters={"url": "https://example.test/debian.iso", "filename": "debian.iso"}
    )

    response = await registry.execute(
        "prepare_vm_install_media",
        request,
        make_context(request, InMemoryProxmoxApiClient()),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["dry_run"] is True
    assert [step["tool"] for step in cast(list[dict[str, object]], result["steps"])] == [
        "download_iso_from_url",
        "attach_iso_to_vm",
    ]
    assert result["mutation_performed"] is False


async def test_create_lxc_from_template_dry_run_plans_template_download_and_create() -> None:
    registry = make_registry()
    request = make_request(
        resource_type="lxc",
        resource_id="101",
        vmid=101,
        parameters={
            "template": "debian-12-standard_12.7-1_amd64.tar.zst",
            "hostname": "mcp-lab-101",
            "password_secret_ref": "secret://lab/lxc-password",
        },
    )

    response = await registry.execute(
        "create_lxc_from_template",
        request,
        make_context(request, InMemoryProxmoxApiClient()),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["dry_run"] is True
    assert result["mutation_performed"] is False
    payload = cast(dict[str, object], cast(list[dict[str, object]], result["steps"])[1]["payload"])
    assert payload["vmid"] == 101
    assert payload["hostname"] == "mcp-lab-101"
    assert payload["ostemplate"] == "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"
    assert payload["password"] == "<secret-ref:secret://lab/lxc-password>"  # noqa: S105


async def test_create_lxc_from_template_live_refuses_unresolved_secret_ref() -> None:
    registry = make_registry()
    client = InMemoryProxmoxApiClient()
    request = make_request(
        resource_type="lxc",
        resource_id="101",
        vmid=101,
        parameters={
            "template": "debian-12-standard_12.7-1_amd64.tar.zst",
            "hostname": "mcp-lab-101",
            "password_secret_ref": "secret://lab/lxc-password",
        },
        dry_run=False,
    )

    response = await registry.execute(
        "create_lxc_from_template", request, make_context(request, client)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
    assert client.requests == []


async def test_run_helper_app_install_dry_run_selects_matching_script() -> None:
    registry = make_registry()
    request = make_request(
        resource_type="node",
        resource_id="pve-1",
        vmid=None,
        parameters={"query": "adguard"},
    )

    response = await registry.execute("run_helper_app_install", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["selected_script_id"] == "ct/adguard.sh"
    assert result["execution_status"] == "preview_only"
