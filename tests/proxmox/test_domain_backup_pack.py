from __future__ import annotations

from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    InMemoryProxmoxApiClient,
    domain_tool_pack_records,
    register_domain_completion_tools,
)
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


def make_registry() -> ToolRegistry:
    registry = ToolRegistry(guard=AllowGuard())
    register_domain_completion_tools(registry)
    return registry


def make_request(
    *,
    parameters: dict[str, object] | None = None,
    dry_run: bool = True,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            cluster="lab",
            node="pve-1",
            resource_type="vm",
            resource_id="100",
            vmid=100,
            storage_id="backup-store",
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


def test_backup_pack_has_concrete_job_and_content_contracts() -> None:
    records = {record.name: record for record in domain_tool_pack_records("backup")}

    assert records["create_backup_job"].endpoint_template == "/cluster/backup"
    assert records["update_backup_job"].endpoint_template == "/cluster/backup/{job_id}"
    assert records["delete_backup_job"].required_parameter_fields == ("job_id",)
    assert records["verify_backup"].endpoint_template == (
        "/nodes/{node}/storage/{storage_id}/content/{volume}"
    )
    assert records["verify_backup"].promotion_status == "guarded_not_implemented"
    assert records["prune_backups"].endpoint_template == (
        "/nodes/{node}/storage/{storage_id}/prunebackups"
    )
    live_records = {name: record for name, record in records.items() if name != "verify_backup"}
    assert all(record.promotion_status == "live_supported" for record in live_records.values())
    assert records["prune_backups"].method == "DELETE"


def test_backup_pack_destructive_prune_requires_approval_by_default() -> None:
    registry = make_registry()

    assert registry.get("prune_backups").approval_default is True


async def test_backup_pack_dry_run_previews_verify_volume_path() -> None:
    registry = make_registry()
    request = make_request(parameters={"volume": "backup:backup/vzdump-qemu-100.vma.zst"})

    response = await registry.execute("verify_backup", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["endpoint"] == (
        "/nodes/pve-1/storage/backup-store/content/backup%3Abackup%2Fvzdump-qemu-100.vma.zst"
    )
    assert result["risk"] == "medium"
    assert result["promotion_status"] == "guarded_not_implemented"


async def test_verify_backup_pbs_dry_run_records_backend_contract() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "volume": "backup:backup/vzdump-qemu-100.vma.zst",
            "payload": {
                "backend": "pbs",
                "repository": "pbs-local",
            },
        }
    )

    response = await registry.execute("verify_backup", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["promotion_status"] == "guarded_not_implemented"
    assert result["payload"] == {
        "backend": "pbs",
        "repository": "pbs-local",
    }
    verification = cast(dict[str, object], result["result"])
    assert verification["backend"] == "pbs"
    assert verification["repository"] == "pbs-local"
    assert verification["artifact"] == "backup:backup/vzdump-qemu-100.vma.zst"
    assert verification["verification_status"] == "guarded"
    assert verification["audit_fields"] == [
        "backend",
        "repository",
        "artifact",
        "verification_source",
        "verification_status",
    ]
    assert "PBS verification requires" in cast(str, result["rollback_guidance"])


async def test_restore_vm_backup_dry_run_returns_restore_preview_evidence() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "payload": {
                "archive": "backup:backup/vzdump-qemu-100.vma.zst",
                "storage": "local-lvm",
            }
        }
    )

    response = await registry.execute("restore_vm_backup", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    preview = cast(dict[str, object], result["result"])
    assert preview["restore_preview"] == {
        "artifact": "backup:backup/vzdump-qemu-100.vma.zst",
        "target_type": "vm",
        "target_id": "100",
        "storage": "local-lvm",
        "artifact_addressability": "check_required",
        "mutation_performed": False,
        "live_mutation_required": True,
        "conflict_check": "required_before_live_restore",
    }
    payload = cast(dict[str, object], result["payload"])
    assert payload["archive"] == "backup:backup/vzdump-qemu-100.vma.zst"


async def test_verify_backup_live_returns_backend_specific_unsupported_response() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "volume": "backup:backup/vzdump-qemu-100.vma.zst",
            "payload": {"backend": "pve-local"},
        },
        dry_run=False,
    )
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("verify_backup", request, make_context(request, client))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
    assert response.error.details == {
        "tool_name": "verify_backup",
        "connector": "proxmox_api",
        "backend": "pve-local",
        "required_evidence": "backend-specific backup verification contract and lab evidence",
    }
    assert client.requests == []


async def test_backup_pack_live_job_update_uses_expected_api_path() -> None:
    registry = make_registry()
    request = make_request(
        parameters={"job_id": "backup-001", "payload": {"enabled": 0}},
        dry_run=False,
    )
    client = InMemoryProxmoxApiClient({"/cluster/backup/backup-001": "UPID:backup"})

    response = await registry.execute("update_backup_job", request, make_context(request, client))

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].method == "PUT"
    assert client.requests[-1].path == "/cluster/backup/backup-001"
    assert client.requests[-1].data == {"enabled": 0}


async def test_backup_pack_prune_scopes_guest_targets_to_authorized_vmid() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"keep-last": 3}})

    response = await registry.execute("prune_backups", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["payload"] == {"keep-last": 3, "vmid": "100", "type": "qemu"}


async def test_backup_pack_rejects_prune_payload_vmid_mismatch() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"vmid": 200}}, dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("prune_backups", request, make_context(request, client))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_backup_pack_requires_job_id_for_delete() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("delete_backup_job", request, make_context(request, client))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_backup_pack_rejects_unsafe_volume_path() -> None:
    registry = make_registry()
    request = make_request(parameters={"volume": "../vzdump-qemu-100.vma.zst"}, dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute("verify_backup", request, make_context(request, client))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []
