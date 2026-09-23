"""Capability roles and admin user capability_role_id.

Revision ID: 202609230003
Revises: 202609230002
Create Date: 2026-09-23 12:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "202609230003"
down_revision: str | None = "202609230002"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "capability_roles",
        sa.Column("role_id", sa.String(length=128), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("base_template", sa.String(length=64), nullable=True),
        sa.Column("granted_tools_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("denied_tools_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("permission_seeds_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("system", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", name="uq_capability_roles_name"),
    )
    with op.batch_alter_table("admin_users") as batch:
        batch.add_column(sa.Column("capability_role_id", sa.String(length=128), nullable=True))
        batch.create_foreign_key(
            "fk_admin_users_capability_role_id",
            "capability_roles",
            ["capability_role_id"],
            ["role_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("admin_users") as batch:
        batch.drop_constraint("fk_admin_users_capability_role_id", type_="foreignkey")
        batch.drop_column("capability_role_id")
    op.drop_table("capability_roles")
