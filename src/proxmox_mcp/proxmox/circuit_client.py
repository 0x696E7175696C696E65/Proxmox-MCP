from __future__ import annotations

from collections.abc import Awaitable, Callable

from proxmox_mcp.proxmox.client import ProxmoxApiClient, ProxmoxApiError
from proxmox_mcp.reliability import CircuitBreaker, CircuitOpenError


class CircuitBreakerProxmoxClient:
    def __init__(self, delegate: ProxmoxApiClient, *, circuit_breaker: CircuitBreaker) -> None:
        self._delegate = delegate
        self._circuit_breaker = circuit_breaker

    async def get(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
    ) -> object:
        return await self._execute(lambda: self._delegate.get(path, params=params))

    async def post(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await self._execute(lambda: self._delegate.post(path, data=data))

    async def put(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await self._execute(lambda: self._delegate.put(path, data=data))

    async def delete(
        self,
        path: str,
        *,
        data: dict[str, object] | None = None,
    ) -> object:
        return await self._execute(lambda: self._delegate.delete(path, data=data))

    async def _execute(self, operation: Callable[[], Awaitable[object]]) -> object:
        self._circuit_breaker.before_call()
        try:
            value = await operation()
        except CircuitOpenError:
            raise
        except ProxmoxApiError as exc:
            if exc.retryable:
                self._circuit_breaker.record_failure()
            raise
        except Exception:
            self._circuit_breaker.record_failure()
            raise
        else:
            self._circuit_breaker.record_success()
            return value
