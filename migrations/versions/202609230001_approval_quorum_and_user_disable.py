"""add approval quorum columns, decisions table, and admin user disabled_at

Revision ID: 202609230001
Revises: 202609220001
Create Date: 2026-09-23 00:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "202609230001"
down_revision: str | None = "202609220001"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column(
        "approval_requests",
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_table(
        "approval_decisions",
        sa.Column("decision_id", sa.String(length=128), primary_key=True),
        sa.Column(
            "approval_request_id",
            sa.String(length=128),
            sa.ForeignKey("approval_requests.approval_request_id", name="fk_approval_decisions_req"),
            nullable=False,
        ),
        sa.Column("approver_user_id", sa.String(length=128), nullable=False),
        sa.Column("approver_username", sa.String(length=128), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("step_up_audit_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_approval_decisions_request_id",
        "approval_decisions",
        ["approval_request_id"],
    )
    op.add_column(
        "admin_users",
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("admin_users", "disabled_at")
    op.drop_index("ix_approval_decisions_request_id", table_name="approval_decisions")
    op.drop_table("approval_decisions")
    op.drop_column("approval_requests", "required_approvals")
