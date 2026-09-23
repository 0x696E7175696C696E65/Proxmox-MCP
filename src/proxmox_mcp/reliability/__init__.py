from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, TypeVar
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.persistence.models import IdempotencyRecord, ProxmoxTaskRecord

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
                expired = _as_aware(record.expires_at) <= now
                failed_completed = record.status == "completed" and record.result_status == "error"
                if expired or failed_completed:
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
            try:
                await session.commit()
            except Exception as exc:
                await session.rollback()
                from sqlalchemy.exc import IntegrityError

                if isinstance(exc, IntegrityError):
                    return IdempotencyClaim(acquired=False, reason="conflict")
                raise
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


@dataclass(frozen=True, slots=True)
class ProxmoxTask:
    task_id: str
    upid: str
    operation: str
    method: str
    endpoint: str
    target: dict[str, object]
    request_fingerprint: str
    idempotency_key: str | None
    status: str
    retryable: bool
    last_observed_state: str | None
    created_at: datetime
    updated_at: datetime


class ProxmoxTaskStore(Protocol):
    async def record_task(
        self,
        *,
        upid: str,
        operation: str,
        method: str,
        endpoint: str,
        target: dict[str, object],
        request_fingerprint: str,
        idempotency_key: str | None,
        status: str = "running",
        retryable: bool = True,
        last_observed_state: str | None = None,
    ) -> ProxmoxTask: ...

    async def get_by_upid(self, upid: str) -> ProxmoxTask: ...

    async def list_tasks(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
        node: str | None = None,
    ) -> list[ProxmoxTask]: ...

    async def update_observed_state(
        self,
        upid: str,
        *,
        status: str,
        last_observed_state: str | None,
    ) -> ProxmoxTask: ...


class DatabaseProxmoxTaskStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record_task(
        self,
        *,
        upid: str,
        operation: str,
        method: str,
        endpoint: str,
        target: dict[str, object],
        request_fingerprint: str,
        idempotency_key: str | None,
        status: str = "running",
        retryable: bool = True,
        last_observed_state: str | None = None,
    ) -> ProxmoxTask:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            existing = await session.scalar(
                select(ProxmoxTaskRecord).where(ProxmoxTaskRecord.upid == upid)
            )
            if existing is not None:
                return _task_from_record(existing)
            record = ProxmoxTaskRecord(
                task_id=f"proxmox_task_{uuid4().hex}",
                upid=upid,
                operation=operation,
                method=method,
                endpoint=endpoint,
                target_json=target,
                request_fingerprint=request_fingerprint,
                idempotency_key=idempotency_key,
                status=status,
                retryable=retryable,
                last_observed_state=last_observed_state,
                created_at=now,
                updated_at=now,
            )
            session.add(record)
            await session.commit()
            return _task_from_record(record)

    async def get_by_upid(self, upid: str) -> ProxmoxTask:
        async with self._session_factory() as session:
            record = await session.scalar(
                select(ProxmoxTaskRecord).where(ProxmoxTaskRecord.upid == upid)
            )
            if record is None:
                raise KeyError(upid)
            return _task_from_record(record)

    async def list_tasks(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
        node: str | None = None,
    ) -> list[ProxmoxTask]:
        async with self._session_factory() as session:
            statement = select(ProxmoxTaskRecord).order_by(ProxmoxTaskRecord.updated_at.desc())
            if status is not None:
                statement = statement.where(ProxmoxTaskRecord.status == status)
            statement = statement.limit(min(max(limit, 1), 500))
            records = list((await session.scalars(statement)).all())
        tasks = [_task_from_record(record) for record in records]
        if node is None:
            return tasks
        return [
            task
            for task in tasks
            if str(task.target.get("node") or "") == node or _node_from_upid(task.upid) == node
        ]

    async def update_observed_state(
        self,
        upid: str,
        *,
        status: str,
        last_observed_state: str | None,
    ) -> ProxmoxTask:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            record = await session.scalar(
                select(ProxmoxTaskRecord).where(ProxmoxTaskRecord.upid == upid)
            )
            if record is None:
                raise KeyError(upid)
            record.status = status
            record.last_observed_state = last_observed_state
            record.updated_at = now
            await session.commit()
            return _task_from_record(record)


class InMemoryProxmoxTaskStore:
    """Test/dev task store with list + refresh semantics."""

    def __init__(self) -> None:
        self._by_upid: dict[str, ProxmoxTask] = {}

    async def record_task(
        self,
        *,
        upid: str,
        operation: str,
        method: str,
        endpoint: str,
        target: dict[str, object],
        request_fingerprint: str,
        idempotency_key: str | None,
        status: str = "running",
        retryable: bool = True,
        last_observed_state: str | None = None,
    ) -> ProxmoxTask:
        existing = self._by_upid.get(upid)
        if existing is not None:
            return existing
        now = datetime.now(UTC)
        task = ProxmoxTask(
            task_id=f"proxmox_task_{uuid4().hex}",
            upid=upid,
            operation=operation,
            method=method,
            endpoint=endpoint,
            target=target,
            request_fingerprint=request_fingerprint,
            idempotency_key=idempotency_key,
            status=status,
            retryable=retryable,
            last_observed_state=last_observed_state,
            created_at=now,
            updated_at=now,
        )
        self._by_upid[upid] = task
        return task

    async def get_by_upid(self, upid: str) -> ProxmoxTask:
        task = self._by_upid.get(upid)
        if task is None:
            raise KeyError(upid)
        return task

    async def list_tasks(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
        node: str | None = None,
    ) -> list[ProxmoxTask]:
        rows = sorted(self._by_upid.values(), key=lambda t: t.updated_at, reverse=True)
        out: list[ProxmoxTask] = []
        for task in rows:
            if status is not None and task.status != status:
                continue
            if node is not None and str(task.target.get("node") or "") != node:
                if _node_from_upid(task.upid) != node:
                    continue
            out.append(task)
            if len(out) >= min(max(limit, 1), 500):
                break
        return out

    async def update_observed_state(
        self,
        upid: str,
        *,
        status: str,
        last_observed_state: str | None,
    ) -> ProxmoxTask:
        task = await self.get_by_upid(upid)
        updated = ProxmoxTask(
            task_id=task.task_id,
            upid=task.upid,
            operation=task.operation,
            method=task.method,
            endpoint=task.endpoint,
            target=task.target,
            request_fingerprint=task.request_fingerprint,
            idempotency_key=task.idempotency_key,
            status=status,
            retryable=task.retryable,
            last_observed_state=last_observed_state,
            created_at=task.created_at,
            updated_at=datetime.now(UTC),
        )
        self._by_upid[upid] = updated
        return updated


def _node_from_upid(upid: str) -> str | None:
    # UPID:<node>:...
    parts = upid.split(":")
    if len(parts) >= 2 and parts[0] == "UPID":
        return parts[1] or None
    return None


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


def _task_from_record(record: ProxmoxTaskRecord) -> ProxmoxTask:
    return ProxmoxTask(
        task_id=record.task_id,
        upid=record.upid,
        operation=record.operation,
        method=record.method,
        endpoint=record.endpoint,
        target=record.target_json,
        request_fingerprint=record.request_fingerprint,
        idempotency_key=record.idempotency_key,
        status=record.status,
        retryable=record.retryable,
        last_observed_state=record.last_observed_state,
        created_at=_as_aware(record.created_at),
        updated_at=_as_aware(record.updated_at),
    )
