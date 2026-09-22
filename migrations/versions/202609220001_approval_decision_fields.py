"""add approval decision audit columns and summary

Revision ID: 202609220001
Revises: 202609210002
Create Date: 2026-09-22 16:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "202609220001"
down_revision: str | None = "202609210002"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column("approval_requests", sa.Column("summary_json", sa.Text(), nullable=True))
    op.add_column(
        "approval_requests", sa.Column("decided_by", sa.String(length=128), nullable=True)
    )
    op.add_column("approval_requests", sa.Column("reason", sa.Text(), nullable=True))
    op.add_column(
        "approval_requests",
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("approval_requests", "decided_at")
    op.drop_column("approval_requests", "reason")
    op.drop_column("approval_requests", "decided_by")
    op.drop_column("approval_requests", "summary_json")
