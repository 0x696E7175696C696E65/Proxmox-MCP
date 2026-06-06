from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Mapping
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from pydantic import SecretStr

from proxmox_mcp.proxmox.client import ProxmoxApiError


class ProxmoxHttpApiClient:
    def __init__(
        self,
        *,
        api_endpoint: str,
        token_id: str,
        token_secret: SecretStr,
        tls_verify: bool = True,
        timeout_seconds: int = 20,
    ) -> None:
        self._api_endpoint = api_endpoint.rstrip("/")
        self._token_id = token_id
        self._token_secret = token_secret
        self._tls_verify = tls_verify
        self._timeout_seconds = timeout_seconds

    async def get(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
    ) -> object:
        return await asyncio.to_thread(
            self._request,
            "GET",
            path,
            params={} if params is None else params,
            data=None,
        )

    async def post(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await asyncio.to_thread(self._request, "POST", path, params={}, data=data)

    async def put(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await asyncio.to_thread(self._request, "PUT", path, params={}, data=data)

    async def delete(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await asyncio.to_thread(self._request, "DELETE", path, params={}, data=data)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, object],
        data: Mapping[str, object] | None,
    ) -> object:
        url = self._url_for(path, params)
        body = None if data is None else urlencode(_string_values(data)).encode()
        request = Request(  # noqa: S310 - lab endpoint is explicitly user configured.
            url,
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": (
                    f"PVEAPIToken={self._token_id}={self._token_secret.get_secret_value()}"
                ),
            },
            method=method,
        )
        if body is not None:
            request.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with urlopen(  # noqa: S310 - lab endpoint is explicitly user configured.
                request,
                timeout=self._timeout_seconds,
                context=self._ssl_context(),
            ) as response:
                payload = response.read()
        except HTTPError as exc:
            raise ProxmoxApiError(
                "Proxmox API returned an error",
                status_code=exc.code,
                retryable=exc.code >= 500,
                details={"path": path, "method": method},
            ) from exc
        except URLError as exc:
            raise ProxmoxApiError(
                "Unable to reach Proxmox API",
                retryable=True,
                details={"path": path, "method": method, "reason": str(exc.reason)},
            ) from exc

        return _decode_proxmox_payload(payload)

    def _url_for(self, path: str, params: Mapping[str, object]) -> str:
        normalized_path = path if path.startswith("/") else f"/{path}"
        url = f"{self._api_endpoint}/api2/json{normalized_path}"
        query = urlencode(_string_values(params))
        if query:
            return f"{url}?{query}"
        return url

    def _ssl_context(self) -> ssl.SSLContext | None:
        if self._tls_verify:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context


def _string_values(values: Mapping[str, object]) -> dict[str, str]:
    return {key: str(value) for key, value in values.items() if value is not None}


def _decode_proxmox_payload(payload: bytes) -> object:
    try:
        decoded: Any = json.loads(payload.decode())
    except json.JSONDecodeError as exc:
        raise ProxmoxApiError("Proxmox API returned invalid JSON", retryable=True) from exc

    if not isinstance(decoded, dict):
        raise ProxmoxApiError("Proxmox API returned an unexpected payload", retryable=True)

    proxmox_payload = cast(Mapping[str, object], decoded)
    return proxmox_payload.get("data")
