"""create admin users and sessions

Revision ID: 202609210001
Revises: 202606060001
Create Date: 2026-09-21 00:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "202609210001"
down_revision: str | None = "202606060001"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_users",
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_admin_users")),
        sa.UniqueConstraint("username", name=op.f("uq_admin_users_username")),
    )
    op.create_table(
        "admin_sessions",
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.Column("csrf_token", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["admin_users.user_id"],
            name=op.f("fk_admin_sessions_user_id"),
        ),
        sa.PrimaryKeyConstraint("session_id", name=op.f("pk_admin_sessions")),
    )


def downgrade() -> None:
    op.drop_table("admin_sessions")
    op.drop_table("admin_users")
