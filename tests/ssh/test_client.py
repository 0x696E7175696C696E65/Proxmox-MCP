from __future__ import annotations

import pytest

from proxmox_mcp.ssh.client import (
    AsyncSshClient,
    SshClientError,
    SshCommand,
    SshConnectionConfig,
    SshTarget,
)


async def test_async_ssh_client_fails_closed_without_known_hosts() -> None:
    # known_hosts defaults to None; asyncssh would otherwise accept any server key.
    # The guard rejects the connection before any network call is attempted.
    client = AsyncSshClient(hosts={"pve-a": SshConnectionConfig(host="10.0.0.1", username="root")})

    with pytest.raises(SshClientError) as exc_info:
        await client.execute(SshTarget(node="pve-a"), SshCommand(command="uptime"))

    assert exc_info.value.error_code == "SSH_CONNECTION_FAILED"
    assert "known_hosts" in str(exc_info.value)
