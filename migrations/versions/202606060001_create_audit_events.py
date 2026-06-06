"""create audit events

Revision ID: 202606060001
Revises:
Create Date: 2026-06-06 00:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "202606060001"
down_revision: str | None = None
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("correlation_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("actor_user_id", sa.String(length=128), nullable=False),
        sa.Column("actor_agent_id", sa.String(length=128), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=256), nullable=False),
        sa.Column("resource_type", sa.String(length=128), nullable=False),
        sa.Column("resource_id", sa.String(length=256), nullable=False),
        sa.Column("cluster_id", sa.String(length=128), nullable=True),
        sa.Column("node_id", sa.String(length=128), nullable=True),
        sa.Column("result_status", sa.String(length=32), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("target_json", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("event_json", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_audit_events")),
    )


def downgrade() -> None:
    op.drop_table("audit_events")
