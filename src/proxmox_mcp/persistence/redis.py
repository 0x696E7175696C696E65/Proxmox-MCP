from __future__ import annotations

from redis.asyncio import Redis

from proxmox_mcp.config import Settings


def build_redis_client(settings: Settings) -> Redis:
    return Redis.from_url(  # pyright: ignore[reportUnknownMemberType]
        settings.redis_url.get_secret_value(),
        decode_responses=True,
    )
