"""Regression tests for LinkedIn/production audit hardening patches."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import RESERVED_MCP_AGENT_IDS, Settings
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest
from proxmox_mcp.security.egress import SECURE_SSH_PATH, https_request_no_redirect
from proxmox_mcp.ssh.client import InMemorySshClient, SshCommand, SshTarget
from proxmox_mcp.ssh.policy import SshCommandPolicy
from proxmox_mcp.ssh.recording import InMemorySshRecordingStore
from proxmox_mcp.ssh.sessions import SshSessionManager
from proxmox_mcp.ssh.tools import register_ssh_tools
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolGuardDecision, ToolRegistry


class _AllowGuard:
    async def evaluate(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolGuardDecision:
        _ = definition, request, context
        return ToolGuardDecision.allowed()


def test_reserved_agent_id_rejected_on_default_actor() -> None:
    with pytest.raises(ValueError, match="reserved"):
        Settings(
            environment="homelab",
            auth_mode="service_token",
            service_token="x" * 32,
            default_actor={"user_id": "operator", "agent_id": "admin-ui"},
        )


def test_reserved_agent_id_rejected_on_service_token_binding() -> None:
    with pytest.raises(ValueError, match="reserved"):
        Settings(
            environment="homelab",
            auth_mode="service_token",
            service_token="x" * 32,
            service_token_actors=(
                {
                    "token_sha256": "a" * 64,
                    "user_id": "attacker",
                    "agent_id": "admin-ui",
                    "role": "read_only",
                },
            ),
        )
    assert "admin-ui" in RESERVED_MCP_AGENT_IDS


def test_ssh_policy_rejects_planted_absolute_tmp_binary() -> None:
    policy = SshCommandPolicy()
    decision = policy.evaluate(SshCommand(command="/tmp/qm list"))
    assert decision.allowed is False


def test_ssh_policy_allows_system_bin_absolute_and_basename() -> None:
    policy = SshCommandPolicy()
    assert policy.evaluate(SshCommand(command="qm list")).allowed is True
    assert policy.evaluate(SshCommand(command="/usr/sbin/qm list")).allowed is True


def test_ssh_policy_denies_destructive_qm_subcommands() -> None:
    policy = SshCommandPolicy()
    assert policy.evaluate(SshCommand(command="qm destroy 100")).allowed is False
    assert policy.evaluate(SshCommand(command="qm stop 100")).allowed is False
    assert policy.evaluate(SshCommand(command="pvesh set /nodes/pve/qemu/100/config")).allowed is False
    assert policy.evaluate(SshCommand(command="pvesh get /cluster/status")).allowed is True
    assert policy.evaluate(SshCommand(command="zpool create tank /dev/sdb")).allowed is True
    assert policy.evaluate(SshCommand(command="zpool destroy tank")).allowed is False
    assert policy.evaluate(SshCommand(command="ceph osd out 1")).allowed is False
    assert policy.evaluate(SshCommand(command="ceph osd reweight 1 0.9")).allowed is True


def test_ssh_policy_default_file_roots_include_pve_and_helpers() -> None:
    policy = SshCommandPolicy()
    assert "/var/lib/vz" in policy.allowed_file_roots
    assert "/var/lib/proxmox-mcp" in policy.allowed_file_roots


def test_secure_ssh_path_constant() -> None:
    assert SECURE_SSH_PATH.startswith("/usr/sbin:")
    assert "/tmp" not in SECURE_SSH_PATH


def test_egress_pins_tcp_to_resolved_ip() -> None:
    """Connect must use the validated IP — never re-resolve hostname at dial time."""
    connected_to: list[tuple[object, ...]] = []

    class _FakeSock:
        def close(self) -> None:
            return None

    def _fake_create_connection(address: tuple[object, ...], timeout: object = None) -> _FakeSock:
        _ = timeout
        connected_to.append(address)
        return _FakeSock()

    class _FakeSslSock(_FakeSock):
        def sendall(self, data: object) -> None:
            _ = data

        def makefile(self, *args: object, **kwargs: object) -> object:
            _ = args, kwargs
            import io

            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    class _FakeResp:
        status = 200

        def read(self) -> bytes:
            return b"{}"

    def _fake_wrap(self: object, sock: object, server_hostname: str | None = None) -> _FakeSslSock:
        _ = self, sock, server_hostname
        return _FakeSslSock()

    with (
        patch("proxmox_mcp.security.egress.socket.create_connection", _fake_create_connection),
        patch("ssl.SSLContext.wrap_socket", _fake_wrap),
        patch("http.client.HTTPSConnection.getresponse", lambda self: _FakeResp()),  # noqa: ARG005
    ):
        status, body = https_request_no_redirect(
            "https://192.168.9.9:8443/health",
            allow_private=True,
            allow_public=False,
        )

    assert status == 200
    assert body == b"{}"
    assert connected_to == [("192.168.9.9", 8443)]


@pytest.mark.asyncio
async def test_download_file_honors_dry_run_without_client_call() -> None:
    registry = ToolRegistry(guard=_AllowGuard())
    register_ssh_tools(registry)
    client = InMemorySshClient(files={"/var/lib/vz/secret.key": "super-secret"})
    request = ToolRequest(
        actor=Actor(user_id="operator", agent_id="homelab-agent"),
        target=Target(resource_type="node", resource_id="pve1", node="pve1"),
        parameters={"remote_path": "/var/lib/vz/secret.key"},
        options=RequestOptions(dry_run=True),
    )
    context = ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        ssh_client=client,
        ssh_command_policy=SshCommandPolicy(),
        ssh_session_manager=SshSessionManager(),
        ssh_recording_store=InMemorySshRecordingStore(),
    )
    response = await registry.execute("download_file", request, context)
    assert getattr(response, "status", None) == "success"
    result = getattr(response, "result", {})
    assert result["dry_run"] is True
    assert not result.get("content")
    assert client.downloads == []


@pytest.mark.asyncio
async def test_close_ssh_session_honors_dry_run() -> None:
    registry = ToolRegistry(guard=_AllowGuard())
    register_ssh_tools(registry)
    manager = SshSessionManager()
    opened = manager.open_session(
        actor=Actor(user_id="operator", agent_id="homelab-agent"),
        target=SshTarget(node="pve1"),
        interactive=False,
    )
    request = ToolRequest(
        actor=Actor(user_id="operator", agent_id="homelab-agent"),
        target=Target(resource_type="node", resource_id="pve1", node="pve1"),
        parameters={"session_id": opened.session_id},
        options=RequestOptions(dry_run=True),
    )
    context = ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        ssh_client=MagicMock(),
        ssh_command_policy=SshCommandPolicy(),
        ssh_session_manager=manager,
        ssh_recording_store=InMemorySshRecordingStore(),
    )
    response = await registry.execute("close_ssh_session", request, context)
    assert getattr(response, "status", None) == "success"
    assert getattr(response, "result", {})["status"] == "would_close"
    assert manager.get_active_session(opened.session_id).active is True


def test_production_probe_refuses_tls_verify_false() -> None:
    from proxmox_mcp.admin.hosts import probe_host_health
    from proxmox_mcp.admin.hosts_store import HostRecord

    state = MagicMock()
    state.settings.environment = "production"
    state.settings.host_allow_public_endpoints = False
    store = MagicMock()
    store.credential_entry.return_value = {"token_id": "u@pve", "token_secret": "s"}
    state.host_catalog = store
    record = HostRecord(
        host_id="h1",
        name="bad",
        api_endpoint="https://192.168.1.10:8006",
        credential_ref_path="clusters/x",
        tls_verify=False,
    )
    result = probe_host_health(state, record)
    assert result["ok"] is False
    assert "tls_verify" in str(result["error"])
