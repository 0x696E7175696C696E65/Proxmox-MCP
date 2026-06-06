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


def make_request(*, dry_run: bool = True) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            cluster="lab",
            node="pve-1",
            resource_type="lxc",
            resource_id="101",
            vmid=101,
        ),
        parameters={},
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
            allowed_executables=frozenset({"pct", "pvesh", "pveversion"})
        ),
    )


def test_ssh_console_pack_promotes_console_and_support_bundle() -> None:
    records = {record.name: record for record in domain_tool_pack_records("ssh_console")}

    assert records["enter_lxc_console"].command_template == "pct enter {vmid}"
    assert records["run_diagnostics"].command_template == "pvesh get /nodes/{node}/status"
    assert records["collect_support_bundle"].command_template is not None
    assert records["enter_lxc_console"].promotion_status == "guarded_not_implemented"
    assert records["run_diagnostics"].promotion_status == "live_supported"
    assert records["collect_support_bundle"].promotion_status == "live_supported"


async def test_lxc_console_dry_run_previews_pct_command() -> None:
    registry = make_registry()
    request = make_request()

    response = await registry.execute("enter_lxc_console", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["command"] == "pct enter 101"
    assert result["risk"] == "high"
    assert result["promotion_status"] == "guarded_not_implemented"


async def test_lxc_console_live_execution_requires_session_backend() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemorySshClient()

    response = await registry.execute(
        "enter_lxc_console",
        request,
        make_context(request, client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
    assert client.executions == []


async def test_collect_support_bundle_live_command_executes() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    command_text = "pveversion -v"
    client = InMemorySshClient(
        command_results={command_text: SshCommandResult(exit_status=0, stdout="bundle")}
    )

    response = await registry.execute(
        "collect_support_bundle",
        request,
        make_context(request, client),
    )

    assert isinstance(response, ToolResponse)
    _, command = client.executions[-1]
    assert command.command == command_text
