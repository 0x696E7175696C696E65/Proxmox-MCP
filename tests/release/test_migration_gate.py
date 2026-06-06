from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from proxmox_mcp.persistence.models import ApprovalRecord, AuditEventRecord, IdempotencyRecord


def _expected_model_columns() -> dict[str, set[str]]:
    return {
        "audit_events": {column.name for column in AuditEventRecord.__table__.columns},
        "approval_requests": {column.name for column in ApprovalRecord.__table__.columns},
        "idempotency_records": {column.name for column in IdempotencyRecord.__table__.columns},
    }


def _assert_migrated_schema_matches_models(database_path: Path) -> None:
    with sqlite3.connect(database_path) as connection:
        table_names = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        migrated_columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
        approval_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(approval_requests)")
        }
        idempotency_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(idempotency_records)")
        }

    assert {
        "alembic_version",
        "approval_requests",
        "audit_events",
        "idempotency_records",
    } <= table_names
    expected_columns = _expected_model_columns()
    assert migrated_columns == expected_columns["audit_events"]
    assert approval_columns == expected_columns["approval_requests"]
    assert idempotency_columns == expected_columns["idempotency_records"]


async def _postgresql_schema_columns(database_url: str) -> dict[str, set[str]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:

            def collect_columns(sync_connection: Connection) -> dict[str, set[str]]:
                inspector = inspect(sync_connection)
                return {
                    table_name: {
                        cast(str, column["name"])
                        for column in cast(list[dict[str, Any]], inspector.get_columns(table_name))
                    }
                    for table_name in (
                        "audit_events",
                        "approval_requests",
                        "idempotency_records",
                    )
                }

            return await connection.run_sync(collect_columns)
    finally:
        await engine.dispose()


def test_alembic_upgrade_creates_schema_matching_models(tmp_path: Path) -> None:
    database_path = tmp_path / "migration-gate.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{database_path.as_posix()}")

    command.upgrade(config, "head")

    _assert_migrated_schema_matches_models(database_path)


def test_alembic_upgrade_creates_schema_matching_postgresql() -> None:
    database_url = os.environ.get("PROXMOX_MCP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("Set PROXMOX_MCP_TEST_POSTGRES_URL to validate PostgreSQL migrations")

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.downgrade(config, "base")
    command.upgrade(config, "head")

    assert asyncio.run(_postgresql_schema_columns(database_url)) == _expected_model_columns()
