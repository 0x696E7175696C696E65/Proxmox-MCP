from __future__ import annotations

from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.ssh import (
    InMemorySshClient,
    InMemorySshRecordingStore,
    SshCommandPolicy,
    SshCommandResult,
    SshSessionManager,
)
from proxmox_mcp.ssh.tools import SSH_TOOL_SPECS, register_ssh_tools
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolGuardDecision, ToolRegistry

UPLOAD_PATH = "/srv/proxmox-mcp/tool.txt"
SOURCE_PATH = "/srv/proxmox-mcp/source.txt"
DESTINATION_PATH = "/srv/proxmox-mcp/destination.txt"
REPORT_DIR = "/srv/proxmox-mcp/reports"
REPORT_PATH = "/srv/proxmox-mcp/reports/report.txt"
MKDIR_PATH = "/srv/proxmox-mcp/work"
DELETE_PATH = "/srv/proxmox-mcp/delete-me.txt"


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
    register_ssh_tools(registry)
    return registry


def make_request(
    *,
    tool: str = "execute_ssh",
    parameters: dict[str, object] | None = None,
    dry_run: bool = True,
) -> ToolRequest:
    _ = tool
    return ToolRequest(
        actor=Actor(user_id="user-1", agent_id="agent-1", tenant_id="tenant-1"),
        target=Target(
            tenant_id="tenant-1",
            cluster="lab",
            node="pve-a",
            resource_type="node",
            resource_id="pve-a",
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


def make_context(
    request: ToolRequest,
    client: InMemorySshClient,
    writer: InMemoryAuditWriter,
    *,
    policy: SshCommandPolicy | None = None,
    session_manager: SshSessionManager | None = None,
    recording_store: InMemorySshRecordingStore | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=writer,
        ssh_client=client,
        ssh_command_policy=SshCommandPolicy() if policy is None else policy,
        ssh_session_manager=SshSessionManager() if session_manager is None else session_manager,
        ssh_recording_store=InMemorySshRecordingStore()
        if recording_store is None
        else recording_store,
    )


async def test_execute_ssh_dry_run_evaluates_policy_without_calling_client() -> None:
    registry = make_registry()
    request = make_request(parameters={"command": "zpool status -x"})
    writer = InMemoryAuditWriter()
    client = InMemorySshClient()

    response = await registry.execute("execute_ssh", request, make_context(request, client, writer))

    assert isinstance(response, ToolResponse)
    assert client.executions == []
    result = cast(dict[str, object], response.result)
    assert result["dry_run"] is True
    assert result["policy_allowed"] is True
    assert isinstance(result["command_hash"], str)


async def test_execute_ssh_denies_shell_metacharacters_by_default() -> None:
    registry = make_registry()
    request = make_request(parameters={"command": "zpool status -x; cat /etc/shadow"})
    writer = InMemoryAuditWriter()
    client = InMemorySshClient()

    response = await registry.execute("execute_ssh", request, make_context(request, client, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "SSH_POLICY_DENIED"
    assert client.executions == []


async def test_execute_ssh_live_records_command_reference_in_result_and_audit() -> None:
    registry = make_registry()
    request = make_request(parameters={"command": "zpool status -x"}, dry_run=False)
    writer = InMemoryAuditWriter()
    client = InMemorySshClient(
        command_results={
            "zpool status -x": SshCommandResult(
                exit_status=0,
                stdout="all pools are healthy token=sensitive",
                stderr="",
                duration_ms=12,
            )
        }
    )
    recording_store = InMemorySshRecordingStore()

    response = await registry.execute(
        "execute_ssh",
        request,
        make_context(request, client, writer, recording_store=recording_store),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["exit_status"] == 0
    assert isinstance(result["recording_ref"], str)
    assert recording_store.recordings[0].stdout == "all pools are healthy token=[REDACTED]"
    assert writer.events[-1].metadata["ssh_recording_ref"] == result["recording_ref"]
    assert writer.events[-1].metadata["ssh_exit_status"] == 0


async def test_open_ssh_session_enforces_per_actor_node_limit() -> None:
    registry = make_registry()
    session_manager = SshSessionManager(max_sessions_per_actor_node=1)
    writer = InMemoryAuditWriter()
    client = InMemorySshClient()
    first = make_request(tool="open_ssh_session", parameters={"reason": "diagnose"}, dry_run=False)
    second = make_request(tool="open_ssh_session", parameters={"reason": "diagnose"}, dry_run=False)

    first_response = await registry.execute(
        "open_ssh_session",
        first,
        make_context(first, client, writer, session_manager=session_manager),
    )
    second_response = await registry.execute(
        "open_ssh_session",
        second,
        make_context(second, client, writer, session_manager=session_manager),
    )

    assert isinstance(first_response, ToolResponse)
    assert isinstance(second_response, ToolErrorResponse)
    assert second_response.error.code == "RATE_LIMITED"


async def test_ssh_sessions_are_sticky_to_session_manager_until_broker_exists() -> None:
    registry = make_registry()
    writer = InMemoryAuditWriter()
    client = InMemorySshClient()
    open_request = make_request(
        tool="open_ssh_session",
        parameters={"reason": "diagnose"},
        dry_run=False,
    )

    open_response = await registry.execute(
        "open_ssh_session",
        open_request,
        make_context(
            open_request,
            client,
            writer,
            session_manager=SshSessionManager(max_sessions_per_actor_node=1),
        ),
    )

    assert isinstance(open_response, ToolResponse)
    result = cast(dict[str, object], open_response.result)
    interactive_request = make_request(
        tool="execute_ssh_interactive",
        parameters={"command": "uptime", "session_id": result["session_id"]},
        dry_run=False,
    )
    second_replica_manager = SshSessionManager(max_sessions_per_actor_node=1)

    interactive_response = await registry.execute(
        "execute_ssh_interactive",
        interactive_request,
        make_context(
            interactive_request,
            client,
            writer,
            session_manager=second_replica_manager,
        ),
    )

    assert isinstance(interactive_response, ToolErrorResponse)
    assert interactive_response.error.code == "NOT_FOUND"


async def test_interactive_execute_requires_active_session() -> None:
    registry = make_registry()
    request = make_request(
        tool="execute_ssh_interactive",
        parameters={"command": "uptime", "session_id": "missing"},
        dry_run=False,
    )
    writer = InMemoryAuditWriter()
    client = InMemorySshClient()

    response = await registry.execute(
        "execute_ssh_interactive",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_FOUND"


async def test_interactive_execute_schema_requires_session_id() -> None:
    registry = make_registry()
    schema = next(item for item in registry.schemas() if item.name == "execute_ssh_interactive")

    parameters_schema = schema.parameters_schema
    assert parameters_schema is not None
    required = parameters_schema["required"]
    assert isinstance(required, list)
    assert "session_id" in required


async def test_interactive_execute_rejects_missing_session_id_before_handler() -> None:
    registry = make_registry()
    request = make_request(
        tool="execute_ssh_interactive",
        parameters={"command": "uptime"},
        dry_run=False,
    )
    writer = InMemoryAuditWriter()
    client = InMemorySshClient()

    response = await registry.execute(
        "execute_ssh_interactive",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.executions == []


async def test_non_dry_run_ssh_tools_reject_dry_run_true() -> None:
    registry = make_registry()
    writer = InMemoryAuditWriter()
    client = InMemorySshClient()
    request = make_request(
        tool="open_ssh_session",
        parameters={"reason": "diagnose"},
        dry_run=True,
    )

    response = await registry.execute(
        "open_ssh_session",
        request,
        make_context(request, client, writer),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert response.error.message == "Tool does not support dry-run requests"


async def test_upload_file_defaults_to_dry_run_without_mutating_client() -> None:
    registry = make_registry()
    request = make_request(
        tool="upload_file",
        parameters={"remote_path": UPLOAD_PATH, "content": "hello"},
    )
    writer = InMemoryAuditWriter()
    client = InMemorySshClient()

    response = await registry.execute("upload_file", request, make_context(request, client, writer))

    assert isinstance(response, ToolResponse)
    assert UPLOAD_PATH not in client.files
    result = cast(dict[str, object], response.result)
    assert result["bytes_transferred"] == 5


async def test_sftp_mkdir_and_scp_copy_live_mutate_client() -> None:
    registry = make_registry()
    writer = InMemoryAuditWriter()
    client = InMemorySshClient(files={SOURCE_PATH: "payload"})
    mkdir_request = make_request(
        tool="sftp_mkdir",
        parameters={"remote_path": MKDIR_PATH, "parents": True},
        dry_run=False,
    )
    copy_request = make_request(
        tool="scp_copy",
        parameters={
            "source_path": SOURCE_PATH,
            "destination_path": DESTINATION_PATH,
        },
        dry_run=False,
    )

    mkdir_response = await registry.execute(
        "sftp_mkdir",
        mkdir_request,
        make_context(mkdir_request, client, writer),
    )
    copy_response = await registry.execute(
        "scp_copy",
        copy_request,
        make_context(copy_request, client, writer),
    )

    assert isinstance(mkdir_response, ToolResponse)
    assert isinstance(copy_response, ToolResponse)
    assert MKDIR_PATH in client.directories
    assert client.files[DESTINATION_PATH] == "payload"


async def test_sftp_list_and_download_return_remote_file_data() -> None:
    registry = make_registry()
    writer = InMemoryAuditWriter()
    client = InMemorySshClient(files={REPORT_PATH: "report"})
    list_request = make_request(
        tool="sftp_list",
        parameters={"remote_path": REPORT_DIR},
        dry_run=False,
    )
    download_request = make_request(
        tool="download_file",
        parameters={"remote_path": REPORT_PATH},
        dry_run=False,
    )

    list_response = await registry.execute(
        "sftp_list",
        list_request,
        make_context(list_request, client, writer),
    )
    download_response = await registry.execute(
        "download_file",
        download_request,
        make_context(download_request, client, writer),
    )

    assert isinstance(list_response, ToolResponse)
    assert isinstance(download_response, ToolResponse)
    list_result = cast(dict[str, object], list_response.result)
    download_result = cast(dict[str, object], download_response.result)
    assert list_result["entries"] == [
        {"path": REPORT_PATH, "name": "report.txt", "kind": "file", "size": 6}
    ]
    assert download_result["content"] == "report"


async def test_sftp_delete_defaults_to_dry_run_and_live_removes_path() -> None:
    registry = make_registry()
    writer = InMemoryAuditWriter()
    client = InMemorySshClient(files={DELETE_PATH: "remove"})
    dry_run_request = make_request(
        tool="sftp_delete",
        parameters={"remote_path": DELETE_PATH},
    )
    live_request = make_request(
        tool="sftp_delete",
        parameters={"remote_path": DELETE_PATH},
        dry_run=False,
    )

    dry_run_response = await registry.execute(
        "sftp_delete",
        dry_run_request,
        make_context(dry_run_request, client, writer),
    )
    assert isinstance(dry_run_response, ToolResponse)
    assert DELETE_PATH in client.files

    live_response = await registry.execute(
        "sftp_delete",
        live_request,
        make_context(live_request, client, writer),
    )

    assert isinstance(live_response, ToolResponse)
    assert DELETE_PATH not in client.files


def test_ssh_tool_schemas_cover_documented_tools() -> None:
    assert {spec.name for spec in SSH_TOOL_SPECS} == {
        "execute_ssh",
        "execute_ssh_interactive",
        "open_ssh_session",
        "close_ssh_session",
        "upload_file",
        "download_file",
        "sftp_list",
        "sftp_mkdir",
        "sftp_delete",
        "scp_copy",
    }
