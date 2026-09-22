from __future__ import annotations

from typing import cast

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import helper_scripts as helper_module
from proxmox_mcp.proxmox import register_helper_script_tools
from proxmox_mcp.proxmox.helper_scripts import (
    HelperScript,
    HelperScriptCatalog,
    HelperScriptCatalogResolver,
    HelperScriptSourceError,
)
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest, ToolResponse
from proxmox_mcp.ssh import InMemorySshClient, SshCommandPolicy
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


class FakeCatalogResolver:
    def __init__(
        self,
        *,
        primary_error: bool = False,
        content: str = "#!/usr/bin/env bash\necho ok\n",
    ) -> None:
        self.primary_error = primary_error
        self.content = content
        self.catalog_calls = 0
        self.content_calls: list[str] = []

    async def load_catalog(self) -> HelperScriptCatalog:
        self.catalog_calls += 1
        if self.primary_error:
            return HelperScriptCatalog(
                source_repo="https://github.com/0x696E7175696C696E65/ProxmoxVE",
                source_commit="fork-commit",
                fallback_used=True,
                scripts=(
                    HelperScript(
                        script_id="ct/adguard.sh",
                        name="adguard",
                        category="ct",
                        path="ct/adguard.sh",
                        download_url=(
                            "https://raw.githubusercontent.com/"
                            "0x696E7175696C696E65/ProxmoxVE/fork-commit/ct/adguard.sh"
                        ),
                        blob_sha="blob-fork",
                        size=42,
                    ),
                ),
            )
        return HelperScriptCatalog(
            source_repo="https://github.com/community-scripts/ProxmoxVE",
            source_commit="primary-commit",
            fallback_used=False,
            scripts=(
                HelperScript(
                    script_id="vm/debian-vm.sh",
                    name="debian-vm",
                    category="vm",
                    path="vm/debian-vm.sh",
                    download_url=(
                        "https://raw.githubusercontent.com/"
                        "community-scripts/ProxmoxVE/primary-commit/vm/debian-vm.sh"
                    ),
                    blob_sha="blob-primary",
                    size=99,
                ),
            ),
        )

    async def fetch_script_content(
        self, script_id: str
    ) -> tuple[HelperScriptCatalog, HelperScript, str]:
        self.content_calls.append(script_id)
        catalog = await self.load_catalog()
        for script in catalog.scripts:
            if script.script_id == script_id:
                return catalog, script, self.content
        raise HelperScriptSourceError("script not found")


class FakeHelperSource:
    repo_url = "https://github.com/community-scripts/ProxmoxVE"

    async def load_catalog(self, *, fallback_used: bool) -> HelperScriptCatalog:
        return HelperScriptCatalog(
            source_repo=self.repo_url,
            source_commit="primary-commit",
            fallback_used=fallback_used,
            scripts=(
                HelperScript(
                    script_id="ct/alpine.sh",
                    name="alpine",
                    category="ct",
                    path="ct/alpine.sh",
                    download_url=(
                        "https://raw.githubusercontent.com/"
                        "community-scripts/ProxmoxVE/primary-commit/ct/alpine.sh"
                    ),
                    blob_sha="blob-primary",
                    size=100,
                ),
            ),
        )

    async def fetch_content(self, script: HelperScript, source_commit: str) -> str:
        _ = script, source_commit
        return (
            "#!/usr/bin/env bash\n"
            "source <(curl -fsSL "
            "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc/build.func)\n"
        )


def make_registry(resolver: FakeCatalogResolver) -> ToolRegistry:
    registry = ToolRegistry(guard=AllowGuard())
    register_helper_script_tools(registry, catalog_resolver=resolver)
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
            resource_type="node",
            resource_id="pve-1",
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


def make_context(
    request: ToolRequest,
    *,
    ssh_client: InMemorySshClient | None = None,
    ssh_policy: SshCommandPolicy | None = None,
    audit_writer: InMemoryAuditWriter | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter() if audit_writer is None else audit_writer,
        ssh_client=ssh_client,
        ssh_command_policy=ssh_policy,
    )


async def test_sync_helper_script_catalog_falls_back_to_user_fork() -> None:
    resolver = FakeCatalogResolver(primary_error=True)
    registry = make_registry(resolver)
    request = make_request(dry_run=False)

    response = await registry.execute("sync_helper_script_catalog", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["fallback_used"] is True
    assert result["source_repo"] == "https://github.com/0x696E7175696C696E65/ProxmoxVE"
    assert cast(list[object], result["scripts"])[0] == {
        "script_id": "ct/adguard.sh",
        "name": "adguard",
        "category": "ct",
        "path": "ct/adguard.sh",
        "download_url": (
            "https://raw.githubusercontent.com/"
            "0x696E7175696C696E65/ProxmoxVE/fork-commit/ct/adguard.sh"
        ),
        "blob_sha": "blob-fork",
        "size": 42,
        "sha256": None,
        "risk_hints": [],
    }


async def test_preview_helper_script_pins_hash_and_detects_risk_hints() -> None:
    resolver = FakeCatalogResolver(
        content=(
            "#!/usr/bin/env bash\n"
            "source <(curl -fsSL "
            "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc/build.func)\n"
            "curl https://example.test | bash\n"
        )
    )
    registry = make_registry(resolver)
    request = make_request(parameters={"script_id": "vm/debian-vm.sh"})

    response = await registry.execute("preview_helper_script", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["source_commit"] == "primary-commit"
    assert isinstance(result["sha256"], str)
    assert "remote_source_execution" in cast(list[str], result["risk_hints"])
    assert "remote_pipe_execution" in cast(list[str], result["risk_hints"])
    assert result["execution_status"] == "preview_only"


async def test_catalog_resolver_rewrites_transitive_raw_main_refs_to_pinned_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_fetch_text(url: str) -> str:
        assert "/primary-commit/" in url
        return "echo pinned dependency\n"

    monkeypatch.setattr(helper_module, "_fetch_text", fake_fetch_text)
    resolver = HelperScriptCatalogResolver(primary=FakeHelperSource())

    _catalog, script, content = await resolver.fetch_script_content("ct/alpine.sh")

    assert "proxmox-mcp inlined helper dependency" in content
    assert "echo pinned dependency" in content
    assert "/main/misc/build.func" not in content
    assert script.sha256 is not None


async def test_stage_helper_script_rejects_free_form_urls() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    request = make_request(parameters={"url": "https://example.test/install.sh"}, dry_run=False)

    response = await registry.execute(
        "stage_helper_script",
        request,
        make_context(request, ssh_client=InMemorySshClient()),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "parameters failed validation" in response.error.message


async def test_preview_helper_script_rejects_path_traversal_script_id() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    request = make_request(parameters={"script_id": "ct/../../evil.sh"})

    response = await registry.execute("preview_helper_script", request, make_context(request))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "allowlisted helper script path" in response.error.message


async def test_stage_helper_script_rejects_sha_mismatch() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    request = make_request(
        parameters={"script_id": "vm/debian-vm.sh", "sha256": "0" * 64},
        dry_run=False,
    )

    response = await registry.execute(
        "stage_helper_script",
        request,
        make_context(request, ssh_client=InMemorySshClient()),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "sha256" in response.error.message


async def test_execute_helper_script_rejects_unapproved_environment_key() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    request = make_request(
        parameters={"script_id": "vm/debian-vm.sh", "environment": {"PATH": "example"}},
        dry_run=False,
    )

    response = await registry.execute(
        "execute_helper_script",
        request,
        make_context(
            request,
            ssh_client=InMemorySshClient(),
            ssh_policy=SshCommandPolicy(
                allowed_executables=frozenset({"env"}),
                denied_executables=frozenset(),
                allowed_environment=frozenset({"var_ctid"}),
                max_timeout_seconds=900,
            ),
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "var_*" in response.error.message


async def test_cancel_helper_script_execution_fails_visibly_on_live() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    request = make_request(parameters={"execution_id": "exec-1"}, dry_run=False)

    response = await registry.execute(
        "cancel_helper_script_execution", request, make_context(request)
    )

    # A live cancel that cannot stop anything must fail visibly, not report success.
    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"


async def test_stage_helper_script_uploads_pinned_artifact_to_controlled_path() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    ssh_client = InMemorySshClient()
    request = make_request(parameters={"script_id": "vm/debian-vm.sh"}, dry_run=False)

    response = await registry.execute(
        "stage_helper_script",
        request,
        make_context(request, ssh_client=ssh_client),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert cast(str, result["remote_path"]).startswith("/var/lib/proxmox-mcp/helpers/")
    assert result["source_commit"] == "primary-commit"
    assert result["fallback_used"] is False
    assert ssh_client.uploads


async def test_execute_helper_script_requires_sha256_pin_for_live_execution() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    ssh_client = InMemorySshClient()
    request = make_request(
        parameters={"script_id": "vm/debian-vm.sh", "mode": "generated"},
        dry_run=False,
    )

    response = await registry.execute(
        "execute_helper_script",
        request,
        make_context(
            request,
            ssh_client=ssh_client,
            ssh_policy=SshCommandPolicy(
                allowed_executables=frozenset({"env"}),
                denied_executables=frozenset(),
                max_timeout_seconds=900,
            ),
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "sha256 pin" in response.error.message
    assert ssh_client.executions == []


async def test_execute_helper_script_rejects_env_value_with_shell_metacharacter() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    ssh_client = InMemorySshClient()
    request = make_request(
        parameters={
            "script_id": "vm/debian-vm.sh",
            "environment": {"var_ctid": "9101;reboot"},
        },
        dry_run=False,
    )

    response = await registry.execute(
        "execute_helper_script",
        request,
        make_context(request, ssh_client=ssh_client, ssh_policy=SshCommandPolicy()),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "unsupported characters" in response.error.message
    assert ssh_client.executions == []


async def test_execute_helper_script_requires_policy_to_allow_bash() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    ssh_client = InMemorySshClient()
    request = make_request(parameters={"script_id": "vm/debian-vm.sh"}, dry_run=False)

    response = await registry.execute(
        "execute_helper_script",
        request,
        make_context(request, ssh_client=ssh_client, ssh_policy=SshCommandPolicy()),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "POLICY_DENIED"
    assert ssh_client.executions == []


async def test_execute_helper_script_fails_closed_without_ssh_policy() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    ssh_client = InMemorySshClient()
    request = make_request(parameters={"script_id": "vm/debian-vm.sh"}, dry_run=False)

    response = await registry.execute(
        "execute_helper_script",
        request,
        make_context(request, ssh_client=ssh_client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "POLICY_DENIED"
    assert ssh_client.executions == []


async def test_run_helper_app_install_live_requires_exact_script_and_hash() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    ssh_client = InMemorySshClient()
    request = make_request(parameters={"query": "debian-vm"}, dry_run=False)

    response = await registry.execute(
        "run_helper_app_install",
        request,
        make_context(
            request,
            ssh_client=ssh_client,
            ssh_policy=SshCommandPolicy(
                allowed_executables=frozenset({"bash"}),
                denied_executables=frozenset(),
                max_timeout_seconds=900,
            ),
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert "script_id and sha256" in response.error.message
    assert ssh_client.executions == []


async def test_stage_helper_script_records_source_metadata_in_audit_event() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    writer = InMemoryAuditWriter()
    request = make_request(parameters={"script_id": "vm/debian-vm.sh"}, dry_run=False)

    response = await registry.execute(
        "stage_helper_script",
        request,
        make_context(request, ssh_client=InMemorySshClient(), audit_writer=writer),
    )

    assert isinstance(response, ToolResponse)
    success_event = writer.events[-1]
    assert success_event.metadata["helper_source_repo"] == (
        "https://github.com/community-scripts/ProxmoxVE"
    )
    assert success_event.metadata["helper_source_commit"] == "primary-commit"
    assert success_event.metadata["helper_blob_sha"] == "blob-primary"
    assert isinstance(success_event.metadata["helper_sha256"], str)
    assert str(success_event.metadata["helper_remote_path"]).startswith(
        "/var/lib/proxmox-mcp/helpers/"
    )


async def test_execute_helper_script_runs_when_policy_explicitly_allows_bash() -> None:
    resolver = FakeCatalogResolver()
    registry = make_registry(resolver)
    ssh_client = InMemorySshClient()

    # Live execution requires an explicit sha256 pin; obtain it from a preview first.
    preview_request = make_request(parameters={"script_id": "vm/debian-vm.sh"})
    preview = await registry.execute(
        "preview_helper_script", preview_request, make_context(preview_request)
    )
    assert isinstance(preview, ToolResponse)
    pinned_sha = cast(str, cast(dict[str, object], preview.result)["sha256"])

    request = make_request(
        parameters={
            "script_id": "vm/debian-vm.sh",
            "sha256": pinned_sha,
            "mode": "generated",
            "environment": {
                "TERM": "xterm",
                "var_ctid": "9101",
                "var_hostname": "mcp-lab-helper",
            },
        },
        dry_run=False,
    )

    response = await registry.execute(
        "execute_helper_script",
        request,
        make_context(
            request,
            ssh_client=ssh_client,
            ssh_policy=SshCommandPolicy(
                allowed_executables=frozenset({"env"}),
                denied_executables=frozenset(),
                allowed_environment=frozenset({"var_ctid", "var_hostname"}),
                max_timeout_seconds=900,
            ),
        ),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["exit_status"] == 0
    assert ssh_client.executions
    _, command = ssh_client.executions[-1]
    assert command.command.startswith(
        "env TERM=xterm mode=generated var_ctid=9101 var_hostname=mcp-lab-helper "
        "bash /var/lib/proxmox-mcp/helpers/"
    )
    assert command.command.endswith("/script.sh generated")
    assert command.environment == {}
