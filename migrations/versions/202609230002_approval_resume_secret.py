"""Add resume_secret_hash for closed-loop agent approval consume.

Revision ID: 202609230002
Revises: 202609230001
Create Date: 2026-09-23 00:01:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "202609230002"
down_revision: str | None = "202609230001"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column(
        "approval_requests",
        sa.Column("resume_secret_hash", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("approval_requests", "resume_secret_hash")
