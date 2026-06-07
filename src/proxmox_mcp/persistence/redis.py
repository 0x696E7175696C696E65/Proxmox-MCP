from __future__ import annotations

from redis import Redis as SyncRedis
from redis.asyncio import Redis as AsyncRedis

from proxmox_mcp.config import Settings


def build_redis_client(settings: Settings) -> AsyncRedis:
    return AsyncRedis.from_url(  # pyright: ignore[reportUnknownMemberType]
        settings.redis_url.get_secret_value(),
        decode_responses=True,
    )


def build_sync_redis_client(settings: Settings) -> SyncRedis:
    return SyncRedis.from_url(  # pyright: ignore[reportUnknownMemberType]
        settings.redis_url.get_secret_value(),
        decode_responses=True,
    )
