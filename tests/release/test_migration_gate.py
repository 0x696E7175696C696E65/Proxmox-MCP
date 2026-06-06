from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config

from proxmox_mcp.persistence.models import ApprovalRecord, AuditEventRecord, IdempotencyRecord


def test_alembic_upgrade_creates_schema_matching_models(tmp_path: Path) -> None:
    database_path = tmp_path / "migration-gate.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{database_path.as_posix()}")

    command.upgrade(config, "head")

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
    assert migrated_columns == {column.name for column in AuditEventRecord.__table__.columns}
    assert approval_columns == {column.name for column in ApprovalRecord.__table__.columns}
    assert idempotency_columns == {column.name for column in IdempotencyRecord.__table__.columns}
