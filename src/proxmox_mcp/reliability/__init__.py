from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, TypeVar

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.persistence.models import IdempotencyRecord

T = TypeVar("T")


class CircuitOpenError(RuntimeError):
    pass


@dataclass(slots=True)
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_seconds: int = 30
    _failure_count: int = 0
    _opened_at: datetime | None = None

    @property
    def open(self) -> bool:
        if self._opened_at is None:
            return False
        if datetime.now(UTC) - self._opened_at >= timedelta(seconds=self.recovery_seconds):
            self._failure_count = 0
            self._opened_at = None
            return False
        return True

    def before_call(self) -> None:
        if self.open:
            raise CircuitOpenError("Circuit is open")

    def record_success(self) -> None:
        self._failure_count = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.failure_threshold:
            self._opened_at = datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    attempts: int = 3
    backoff_seconds: float = 0.05

    async def run(self, operation: Callable[[], Awaitable[T]]) -> T:
        last_error: Exception | None = None
        for attempt in range(self.attempts):
            try:
                return await operation()
            except Exception as exc:
                last_error = exc
                if attempt + 1 >= self.attempts:
                    break
                await asyncio.sleep(self.backoff_seconds * (2**attempt))
        if last_error is None:
            raise RuntimeError("Retry policy executed without attempts")
        raise last_error


@dataclass(frozen=True, slots=True)
class IdempotencyClaim:
    acquired: bool
    reason: str | None = None


class IdempotencyStore(Protocol):
    async def begin(
        self,
        *,
        idempotency_key: str,
        request_fingerprint: str,
        ttl_seconds: int = 3600,
    ) -> IdempotencyClaim: ...

    async def complete(
        self,
        *,
        idempotency_key: str,
        request_fingerprint: str,
        result_status: str,
        error_code: str | None = None,
    ) -> None: ...


class DatabaseIdempotencyStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def begin(
        self,
        *,
        idempotency_key: str,
        request_fingerprint: str,
        ttl_seconds: int = 3600,
    ) -> IdempotencyClaim:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            record = await session.scalar(
                select(IdempotencyRecord).where(
                    IdempotencyRecord.idempotency_key == idempotency_key
                )
            )
            if record is not None:
                if record.request_fingerprint != request_fingerprint:
                    return IdempotencyClaim(acquired=False, reason="fingerprint_mismatch")
                if _as_aware(record.expires_at) <= now:
                    await session.delete(record)
                    await session.commit()
                else:
                    return IdempotencyClaim(acquired=False, reason=record.status)

            session.add(
                IdempotencyRecord(
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint,
                    status="in_progress",
                    created_at=now,
                    updated_at=now,
                    expires_at=now + timedelta(seconds=ttl_seconds),
                )
            )
            await session.commit()
            return IdempotencyClaim(acquired=True)

    async def complete(
        self,
        *,
        idempotency_key: str,
        request_fingerprint: str,
        result_status: str,
        error_code: str | None = None,
    ) -> None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            await session.execute(
                update(IdempotencyRecord)
                .where(IdempotencyRecord.idempotency_key == idempotency_key)
                .where(IdempotencyRecord.request_fingerprint == request_fingerprint)
                .values(
                    status="completed",
                    result_status=result_status,
                    error_code=error_code,
                    updated_at=now,
                )
            )
            await session.commit()


class RedisLockClient(Protocol):
    async def set(
        self,
        name: str,
        value: str,
        *,
        nx: bool,
        ex: int,
    ) -> object: ...

    async def get(self, name: str) -> object: ...

    async def delete(self, name: str) -> object: ...


@dataclass(frozen=True, slots=True)
class RedisLockManager:
    client: RedisLockClient
    namespace: str = "proxmox_mcp:lock"

    async def acquire(self, key: str, owner: str, *, ttl_seconds: int = 60) -> bool:
        result = await self.client.set(
            f"{self.namespace}:{key}",
            owner,
            nx=True,
            ex=ttl_seconds,
        )
        return bool(result)

    async def release(self, key: str, owner: str) -> bool:
        lock_key = f"{self.namespace}:{key}"
        current_owner = await self.client.get(lock_key)
        if current_owner != owner:
            return False
        await self.client.delete(lock_key)
        return True


def request_fingerprint(payload: object) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _as_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
