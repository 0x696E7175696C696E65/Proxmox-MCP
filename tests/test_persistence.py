from typing import cast

from pydantic import SecretStr

from proxmox_mcp.config import Settings
from proxmox_mcp.persistence.database import build_async_engine, build_session_factory
from proxmox_mcp.persistence.redis import build_redis_client


def test_database_engine_uses_configured_url() -> None:
    settings = Settings(
        database_url=SecretStr("postgresql+asyncpg://user:pass@example/app?ssl=require")
    )

    engine = build_async_engine(settings)

    assert str(engine.url).startswith("postgresql+asyncpg://user:***@example/app")
    assert engine.url.query["ssl"] == "require"


def test_session_factory_is_bound_to_engine() -> None:
    settings = Settings(
        database_url=SecretStr("postgresql+asyncpg://user:pass@example/app?ssl=require")
    )
    engine = build_async_engine(settings)

    session_factory = build_session_factory(engine)

    assert session_factory.kw["bind"] is engine


def test_redis_client_uses_configured_url() -> None:
    settings = Settings(redis_url=SecretStr("rediss://redis.example:6379/5"))

    client = build_redis_client(settings)
    pool = client.connection_pool
    raw_kwargs = pool.connection_kwargs  # pyright: ignore
    connection_kwargs = cast("dict[str, object]", raw_kwargs)

    assert connection_kwargs["host"] == "redis.example"
    assert connection_kwargs["db"] == 5
