from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote
from uuid import uuid4

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.proxmox import register_domain_completion_tools
from proxmox_mcp.proxmox.client import ProxmoxApiError
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig
from proxmox_mcp.proxmox.lab_resources import DisposableProxmoxResources
from proxmox_mcp.rbac import RoleAssignment
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.registry import ToolRegistry

pytestmark = pytest.mark.lab


def test_pbs_backup_verification_requires_profile_prerequisites(
    lab_config: LabEnvironmentConfig,
) -> None:
    if lab_config.profile != "pve-9-pbs-enabled":
        pytest.skip("Select PROXMOX_MCP_LAB_PROFILE=pve-9-pbs-enabled for PBS verification")

    missing = lab_config.profile_missing_prerequisites()
    if missing:
        pytest.skip("; ".join(missing))

    pytest.skip(
        "Live PBS verification is not promoted until repository visibility, artifact addressing, "
        "and verification command/source semantics are recorded in release evidence"
    )


async def test_disposable_backup_records_restore_preconditions(
    lab_config: LabEnvironmentConfig,
    lab_client: ProxmoxHttpApiClient,
    lab_resources: DisposableProxmoxResources,
    lab_read_role_assignment: RoleAssignment,
    lab_tool_context_factory: Any,
    optional_lab_node: str,
    optional_lab_storage: str,
    disposable_lab_vmid: int,
) -> None:
    _ = lab_config
    backup_volids_before = await _backup_volids(lab_client, optional_lab_node, optional_lab_storage)

    try:
        await lab_resources.delete_vm_if_present(disposable_lab_vmid)
        await lab_resources.create_vm(disposable_lab_vmid)
        backup_result = await lab_client.post(
            f"/nodes/{optional_lab_node}/vzdump",
            data={
                "vmid": disposable_lab_vmid,
                "storage": optional_lab_storage,
                "mode": "snapshot",
                "compress": "zstd",
            },
        )
        await lab_resources.wait_for_task(backup_result)
        backup_volids_after = await _backup_volids(
            lab_client,
            optional_lab_node,
            optional_lab_storage,
        )
        artifact = _new_backup_for_vmid(
            backup_volids_before,
            backup_volids_after,
            disposable_lab_vmid,
        )
        if artifact is None:
            pytest.skip("Backup completed but no disposable artifact was discoverable")

        registry = ToolRegistry(
            guard=SecurityPlaneGuard(role_assignments=(lab_read_role_assignment,))
        )
        register_domain_completion_tools(registry)
        request = ToolRequest(
            request_id=f"lab-{uuid4()}",
            actor=Actor(user_id="lab_user", agent_id="lab_agent", tenant_id="lab_tenant"),
            target=Target(
                tenant_id="lab_tenant",
                cluster=lab_config.cluster_id,
                node=optional_lab_node,
                resource_type="vm",
                resource_id=str(disposable_lab_vmid),
                vmid=disposable_lab_vmid,
                storage_id=optional_lab_storage,
            ),
            parameters={
                "payload": {
                    "archive": artifact,
                    "storage": optional_lab_storage,
                }
            },
            options=RequestOptions(dry_run=True),
        )
        response = await registry.execute(
            "restore_vm_backup",
            request,
            lab_tool_context_factory(request, lab_client, InMemoryAuditWriter()),
        )
        assert isinstance(response, ToolResponse)
        result = cast(dict[str, object], response.result)
        preview = cast(
            dict[str, object], cast(dict[str, object], result["result"])["restore_preview"]
        )
        assert preview["artifact_addressability"] == "found"
        assert preview["target_conflict"] == "present"
        assert preview["mutation_performed"] is False
    finally:
        backup_volids_after_cleanup = await _backup_volids(
            lab_client,
            optional_lab_node,
            optional_lab_storage,
        )
        for volid in backup_volids_after_cleanup:
            if _is_backup_for_vmid(volid, disposable_lab_vmid):
                await _delete_storage_content(lab_client, optional_lab_node, volid)
        await lab_resources.delete_vm_if_present(disposable_lab_vmid)


async def _backup_volids(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    storage: str,
) -> set[str]:
    content = await lab_client.get(
        f"/nodes/{node}/storage/{storage}/content",
        params={"content": "backup"},
    )
    if not isinstance(content, list):
        return set()
    volids: set[str] = set()
    for item in cast(list[object], content):
        if not isinstance(item, dict):
            continue
        volid = cast(dict[str, object], item).get("volid")
        if isinstance(volid, str):
            volids.add(volid)
    return volids


def _new_backup_for_vmid(before: set[str], after: set[str], vmid: int) -> str | None:
    for volid in sorted(after - before):
        if _is_backup_for_vmid(volid, vmid):
            return volid
    return None


def _is_backup_for_vmid(volid: str, vmid: int) -> bool:
    return f"vzdump-qemu-{vmid}-" in volid or f"vzdump-qemu-{vmid}." in volid


async def _delete_storage_content(
    lab_client: ProxmoxHttpApiClient,
    node: str,
    volid: str,
) -> None:
    try:
        await lab_client.delete(
            f"/nodes/{node}/storage/{volid.split(':', 1)[0]}/content/{quote(volid, safe='')}"
        )
    except ProxmoxApiError:
        return
