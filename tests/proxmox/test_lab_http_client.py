from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretStr

import proxmox_mcp.proxmox.http_client as http_client_module
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient


def _fake_https_request(
    *,
    responses: list[tuple[int, bytes]] | None = None,
    calls: list[dict[str, Any]] | None = None,
    raise_exc: BaseException | None = None,
):
    queue = list(responses or [])

    def _request(
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        timeout_seconds: float = 10,
        ssl_context: object | None = None,
        allow_private: bool = False,
        allow_public: bool = False,
    ) -> tuple[int, bytes]:
        _ = timeout_seconds, ssl_context
        if calls is not None:
            calls.append(
                {
                    "url": url,
                    "method": method,
                    "headers": dict(headers or {}),
                    "data": data,
                    "allow_private": allow_private,
                    "allow_public": allow_public,
                }
            )
        if raise_exc is not None:
            raise raise_exc
        if not queue:
            return 200, json.dumps({"data": None}).encode()
        return queue.pop(0)

    return _request


@pytest.mark.asyncio
async def test_username_password_client_uses_ticket_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    ticket_body = json.dumps(
        {
            "data": {
                "ticket": "ticket-value",
                "CSRFPreventionToken": "csrf-value",
            }
        }
    ).encode()
    nodes_body = json.dumps({"data": [{"node": "pve-a"}]}).encode()
    monkeypatch.setattr(
        http_client_module,
        "https_request_no_redirect",
        _fake_https_request(responses=[(200, ticket_body), (200, nodes_body)], calls=calls),
    )
    client = ProxmoxHttpApiClient(
        api_endpoint="https://pve.example.test:8006",
        username="root@pam",
        password=SecretStr("secret-value"),
        allow_public_endpoint=True,
    )

    result = await client.get("/nodes")

    assert result == [{"node": "pve-a"}]
    assert len(calls) == 2
    ticket_request, nodes_request = calls
    assert ticket_request["url"].endswith("/api2/json/access/ticket")
    assert ticket_request["data"] == b"username=root%40pam&password=secret-value"
    assert nodes_request["headers"].get("Cookie") == "PVEAuthCookie=ticket-value"
    assert "Authorization" not in nodes_request["headers"]
    assert ticket_request["allow_private"] is True


@pytest.mark.asyncio
async def test_delete_sends_parameters_in_query_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        http_client_module,
        "https_request_no_redirect",
        _fake_https_request(responses=[(200, json.dumps({"data": None}).encode())], calls=calls),
    )
    client = ProxmoxHttpApiClient(
        api_endpoint="https://pve.example.test:8006",
        token_id="root@pam!mcp",  # noqa: S106
        token_secret=SecretStr("secret-value"),
        allow_public_endpoint=True,
    )

    await client.delete("/nodes/test/qemu/9000", data={"purge": 1})

    assert (
        calls[0]["url"]
        == "https://pve.example.test:8006/api2/json/nodes/test/qemu/9000?purge=1"
    )
    assert calls[0]["data"] is None


@pytest.mark.asyncio
async def test_timeout_error_maps_to_retryable_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from proxmox_mcp.proxmox.client import ProxmoxApiError

    monkeypatch.setattr(
        http_client_module,
        "https_request_no_redirect",
        _fake_https_request(raise_exc=TimeoutError("timed out")),
    )
    client = ProxmoxHttpApiClient(
        api_endpoint="https://pve.example.test:8006",
        token_id="user@pam!token",
        token_secret=SecretStr("secret"),
        allow_public_endpoint=True,
    )

    with pytest.raises(ProxmoxApiError) as exc_info:
        await client.get("/nodes")

    assert exc_info.value.error_code == "TIMEOUT"
