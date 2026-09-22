from __future__ import annotations

import json
from typing import cast
from urllib.request import Request

import pytest
from pydantic import SecretStr

import proxmox_mcp.proxmox.http_client as http_client_module
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        _ = args

    def read(self) -> bytes:
        return json.dumps({"data": self._payload}).encode()


@pytest.mark.asyncio
async def test_username_password_client_uses_ticket_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[Request] = []

    def fake_urlopen(
        request: Request,
        *,
        timeout: int,
        context: object,
    ) -> FakeResponse:
        _ = timeout, context
        requests.append(request)
        if request.full_url.endswith("/access/ticket"):
            return FakeResponse(
                {
                    "ticket": "ticket-value",
                    "CSRFPreventionToken": "csrf-value",
                }
            )
        return FakeResponse([{"node": "pve-a"}])

    monkeypatch.setattr(http_client_module, "urlopen", fake_urlopen)
    client = ProxmoxHttpApiClient(
        api_endpoint="https://pve.example.test:8006",
        username="root@pam",
        password=SecretStr("secret-value"),
    )

    result = await client.get("/nodes")

    assert result == [{"node": "pve-a"}]
    assert len(requests) == 2
    ticket_request, nodes_request = requests
    assert ticket_request.full_url.endswith("/api2/json/access/ticket")
    assert _request_body(ticket_request) == "username=root%40pam&password=secret-value"
    assert nodes_request.get_header("Cookie") == "PVEAuthCookie=ticket-value"
    assert nodes_request.get_header("Authorization") is None


@pytest.mark.asyncio
async def test_delete_sends_parameters_in_query_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[Request] = []

    def fake_urlopen(
        request: Request,
        *,
        timeout: int,
        context: object,
    ) -> FakeResponse:
        _ = timeout, context
        requests.append(request)
        return FakeResponse(None)

    monkeypatch.setattr(http_client_module, "urlopen", fake_urlopen)
    client = ProxmoxHttpApiClient(
        api_endpoint="https://pve.example.test:8006",
        token_id="root@pam!mcp",  # noqa: S106
        token_secret=SecretStr("secret-value"),
    )

    await client.delete("/nodes/test/qemu/9000", data={"purge": 1})

    assert (
        requests[0].full_url
        == "https://pve.example.test:8006/api2/json/nodes/test/qemu/9000?purge=1"
    )
    assert requests[0].data is None


@pytest.mark.asyncio
async def test_timeout_error_maps_to_retryable_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from proxmox_mcp.proxmox.client import ProxmoxApiError

    def fake_urlopen(*_args: object, **_kwargs: object) -> object:
        raise TimeoutError("timed out")

    monkeypatch.setattr(http_client_module, "urlopen", fake_urlopen)
    client = ProxmoxHttpApiClient(
        api_endpoint="https://pve.example.test:8006",
        token_id="user@pam!token",
        token_secret=SecretStr("secret"),
    )

    with pytest.raises(ProxmoxApiError) as exc_info:
        await client.get("/nodes")

    assert exc_info.value.error_code == "TIMEOUT"
    assert exc_info.value.retryable is True


def _request_body(request: Request) -> str:
    data = request.data
    assert data is not None
    return cast(bytes, data).decode()
