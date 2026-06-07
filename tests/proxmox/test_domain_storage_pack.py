from __future__ import annotations

from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import domain_tool_pack_records, register_domain_completion_tools
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.ssh import InMemorySshClient, SshCommandPolicy, SshCommandResult
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
            resource_type="storage",
            resource_id="local-zfs",
            storage_id="local-zfs",
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


def make_context(
    request: ToolRequest, ssh_client: InMemorySshClient | None = None
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        ssh_client=ssh_client,
        ssh_command_policy=SshCommandPolicy(
            allowed_executables=frozenset({"zpool", "pvesm", "wipefs"})
        ),
    )


def test_storage_pack_promotion_records_identify_live_and_guarded_tools() -> None:
    records = {record.name: record for record in domain_tool_pack_records("storage")}

    assert records["create_zfs_pool"].command_template == "zpool create {pool} {device}"
    assert records["scrub_zfs_pool"].command_template == "zpool scrub {pool}"
    assert records["create_lvm_storage"].command_template == (
        "pvesm add lvm {storage_id} --vgname {volume}"
    )
    assert records["wipe_disk"].command_template == "wipefs -a {device}"
    assert records["create_zfs_pool"].promotion_status == "live_supported"
    assert records["wipe_disk"].promotion_status == "live_supported"

    assert records["expand_storage"].promotion_status == "guarded_not_implemented"
    assert records["benchmark_storage"].promotion_status == "guarded_not_implemented"


async def test_storage_pack_dry_run_requires_command_fields() -> None:
    registry = make_registry()
    request = make_request(parameters={"pool": "tank"})

    response = await registry.execute("create_zfs_pool", request, make_context(request))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"


async def test_storage_pack_dry_run_previews_critical_command() -> None:
    registry = make_registry()
    request = make_request(parameters={"pool": "tank", "device": "/dev/sdb"})

    response = await registry.execute("create_zfs_pool", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["command"] == "zpool create tank /dev/sdb"
    assert result["risk"] == "critical"
    assert result["promotion_status"] == "live_supported"
    assert "verified backup" in cast(str, result["rollback_guidance"])


async def test_storage_pack_live_ssh_command_executes_when_policy_allows() -> None:
    registry = make_registry()
    request = make_request(parameters={"pool": "tank"}, dry_run=False)
    client = InMemorySshClient(
        command_results={"zpool scrub tank": SshCommandResult(exit_status=0, stdout="started")}
    )

    response = await registry.execute("scrub_zfs_pool", request, make_context(request, client))

    assert isinstance(response, ToolResponse)
    _, command = client.executions[-1]
    assert command.command == "zpool scrub tank"


async def test_expand_storage_local_lvm_dry_run_records_backend_preview_contract() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "payload": {
                "backend": "lvmthin",
                "requested_size": "+10G",
            }
        }
    )

    response = await registry.execute("expand_storage", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["promotion_status"] == "guarded_not_implemented"
    assert result["payload"] == {
        "backend": "lvmthin",
        "requested_size": "+10G",
        "mode": "preview",
    }
    expansion_plan = cast(dict[str, object], result["result"])
    assert expansion_plan["backend"] == "lvmthin"
    assert expansion_plan["storage_id"] == "local-zfs"
    assert expansion_plan["requested_size"] == "+10G"
    assert expansion_plan["execution_status"] == "guarded"
    assert expansion_plan["preflight_checks"] == [
        "backend_type",
        "free_space",
        "thin_pool_health",
        "rollback_feasibility",
        "lab_profile_evidence",
    ]
    assert expansion_plan["audit_fields"] == [
        "backend",
        "storage_id",
        "requested_size",
        "execution_status",
    ]
    assert "backend-specific expansion" in cast(str, result["rollback_guidance"])


async def test_expand_storage_lvmthin_requires_requested_size() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"backend": "lvmthin"}})

    response = await registry.execute("expand_storage", request, make_context(request))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "requested_size" in response.error.message


async def test_expand_storage_live_returns_backend_specific_guard() -> None:
    registry = make_registry()
    request = make_request(
        parameters={"payload": {"backend": "lvmthin", "requested_size": "+10G"}},
        dry_run=False,
    )
    client = InMemorySshClient()

    response = await registry.execute("expand_storage", request, make_context(request, client))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
    assert response.error.details == {
        "tool_name": "expand_storage",
        "connector": "hybrid",
        "backend": "lvmthin",
        "required_evidence": "backend-specific storage expansion contract and lab evidence",
    }
    assert client.executions == []


async def test_benchmark_storage_requires_bounded_runtime_settings() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "payload": {
                "target_type": "storage",
                "duration_seconds": 600,
            }
        }
    )

    response = await registry.execute("benchmark_storage", request, make_context(request))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "duration_seconds" in response.error.message


async def test_benchmark_storage_requires_max_bytes_bound() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "payload": {
                "target_type": "storage",
                "duration_seconds": 30,
            }
        }
    )

    response = await registry.execute("benchmark_storage", request, make_context(request))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "max_bytes" in response.error.message


async def test_benchmark_storage_dry_run_returns_bounded_cleanup_plan() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "payload": {
                "backend": "dir",
                "target_type": "storage",
                "duration_seconds": 30,
                "max_bytes": 1048576,
            }
        }
    )

    response = await registry.execute("benchmark_storage", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    benchmark_plan = cast(dict[str, object], result["result"])
    assert benchmark_plan["execution_status"] == "guarded"
    assert benchmark_plan["cleanup_required"] is True
    assert benchmark_plan["timeout_seconds"] == 35
    assert benchmark_plan["artifact_scope"] == "disposable"
    assert benchmark_plan["result_schema"] == [
        "throughput_bytes_per_second",
        "duration_seconds",
        "artifact_path",
        "cleanup_status",
        "command_hash",
    ]


async def test_storage_pack_nonzero_ssh_exit_returns_error() -> None:
    registry = make_registry()
    request = make_request(parameters={"pool": "tank", "device": "/dev/sdb"}, dry_run=False)
    client = InMemorySshClient(
        command_results={
            "zpool create tank /dev/sdb": SshCommandResult(
                exit_status=1,
                stdout="",
                stderr="busy",
            )
        }
    )

    response = await registry.execute("create_zfs_pool", request, make_context(request, client))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "SSH_COMMAND_FAILED"
    assert response.error.details["redacted"] is True
    assert "stderr" not in response.error.details


async def test_storage_pack_rejects_option_like_command_operands() -> None:
    registry = make_registry()
    request = make_request(parameters={"pool": "-f", "device": "/dev/sdb"})

    response = await registry.execute("create_zfs_pool", request, make_context(request))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"


async def test_storage_pack_rejects_unsafe_disk_path_segment() -> None:
    registry = make_registry()
    request = make_request(parameters={"device": "../sdb"}, dry_run=False)
    client = InMemorySshClient()

    response = await registry.execute("wipe_disk", request, make_context(request, client))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.executions == []
