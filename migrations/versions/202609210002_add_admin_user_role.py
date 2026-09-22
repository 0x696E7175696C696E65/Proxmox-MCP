"""add admin user role

Revision ID: 202609210002
Revises: 202609210001
Create Date: 2026-09-21 02:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "202609210002"
down_revision: str | None = "202609210001"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column(
        "admin_users",
        sa.Column("role", sa.String(length=32), nullable=False, server_default="admin"),
    )


def downgrade() -> None:
    op.drop_column("admin_users", "role")
