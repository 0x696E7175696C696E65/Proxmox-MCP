from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from proxmox_mcp.schemas.envelope import ErrorCode


class ProxmoxApiError(RuntimeError):
    def __init__(
        self,
        message: str = "Proxmox API request failed",
        *,
        error_code: ErrorCode = "PROXMOX_API_ERROR",
        status_code: int | None = None,
        retryable: bool = True,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code: ErrorCode = error_code
        self.status_code: int | None = status_code
        self.retryable: bool = retryable
        self.details: dict[str, object] = {} if details is None else details


class ProxmoxApiClient(Protocol):
    async def get(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
    ) -> object: ...

    async def post(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object: ...

    async def put(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object: ...

    async def delete(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object: ...


def _empty_params() -> dict[str, object]:
    return {}


@dataclass(frozen=True, slots=True)
class ProxmoxApiRequest:
    method: str
    path: str
    params: dict[str, object] = field(default_factory=_empty_params)
    data: dict[str, object] = field(default_factory=_empty_params)


class InMemoryProxmoxApiClient:
    def __init__(self, responses: dict[str, object] | None = None) -> None:
        self._responses: dict[str, object] = {} if responses is None else dict(responses)
        self.requests: list[ProxmoxApiRequest] = []

    async def get(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
    ) -> object:
        normalized_params: dict[str, object] = {} if params is None else dict(params)
        self.requests.append(ProxmoxApiRequest(method="GET", path=path, params=normalized_params))
        try:
            return self._responses[path]
        except KeyError as exc:
            raise ProxmoxApiError(
                "No in-memory response configured",
                error_code="NOT_FOUND",
                status_code=404,
                retryable=False,
            ) from exc

    async def post(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await self._write("POST", path, data=data)

    async def put(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await self._write("PUT", path, data=data)

    async def delete(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await self._write("DELETE", path, data=data)

    async def _write(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        normalized_data: dict[str, object] = {} if data is None else dict(data)
        self.requests.append(ProxmoxApiRequest(method=method, path=path, data=normalized_data))
        try:
            return self._responses[path]
        except KeyError as exc:
            raise ProxmoxApiError(
                "No in-memory response configured",
                error_code="NOT_FOUND",
                status_code=404,
                retryable=False,
            ) from exc
