from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine

from proxmox_mcp.persistence.database import build_session_factory
from proxmox_mcp.persistence.models import Base
from proxmox_mcp.reliability import (
    DatabaseIdempotencyStore,
    RedisLockManager,
    request_fingerprint,
)


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, name: str, value: str, *, nx: bool, ex: int) -> object:
        _ = ex
        if nx and name in self.values:
            return None
        self.values[name] = value
        return True

    async def get(self, name: str) -> object:
        return self.values.get(name)

    async def delete(self, name: str) -> object:
        self.values.pop(name, None)
        return 1


async def test_database_idempotency_store_rejects_duplicate_claims(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'idem.db').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    store_a = DatabaseIdempotencyStore(build_session_factory(engine))
    store_b = DatabaseIdempotencyStore(build_session_factory(engine))
    fingerprint = request_fingerprint({"tool": "create_vm", "parameters": {"vmid": 100}})

    first = await store_a.begin(
        idempotency_key="idem-key",
        request_fingerprint=fingerprint,
    )
    await store_a.complete(
        idempotency_key="idem-key",
        request_fingerprint=fingerprint,
        result_status="success",
    )
    second = await store_b.begin(
        idempotency_key="idem-key",
        request_fingerprint=fingerprint,
    )
    conflict = await store_b.begin(
        idempotency_key="idem-key",
        request_fingerprint=request_fingerprint({"tool": "delete_vm"}),
    )
    await engine.dispose()

    assert first.acquired is True
    assert second.acquired is False
    assert second.reason == "completed"
    assert conflict.acquired is False
    assert conflict.reason == "fingerprint_mismatch"


async def test_redis_lock_manager_acquires_and_releases_owned_lock() -> None:
    redis = FakeRedis()
    manager = RedisLockManager(redis)

    assert await manager.acquire("create-vm", "worker-a") is True
    assert await manager.acquire("create-vm", "worker-b") is False
    assert await manager.release("create-vm", "worker-b") is False
    assert await manager.release("create-vm", "worker-a") is True
    assert await manager.acquire("create-vm", "worker-b") is True
