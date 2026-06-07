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
        "approval_requests",
        sa.Column("approval_request_id", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=256), nullable=False),
        sa.Column("target_hash", sa.String(length=64), nullable=False),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("approval_token_hash", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.String(length=128), nullable=False),
        sa.Column("actor_agent_id", sa.String(length=128), nullable=False),
        sa.Column("actor_tenant_id", sa.String(length=128), nullable=True),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("approval_request_id", name=op.f("pk_approval_requests")),
        sa.UniqueConstraint(
            "approval_token_hash",
            name=op.f("uq_approval_requests_approval_token_hash"),
        ),
    )
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
    op.create_table(
        "idempotency_records",
        sa.Column("idempotency_key", sa.String(length=256), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("result_status", sa.String(length=32), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("idempotency_key", name=op.f("pk_idempotency_records")),
    )
    op.create_table(
        "proxmox_tasks",
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("upid", sa.String(length=512), nullable=False),
        sa.Column("operation", sa.String(length=256), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("endpoint", sa.String(length=512), nullable=False),
        sa.Column("target_json", sa.JSON(), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=256), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("retryable", sa.Boolean(), nullable=False),
        sa.Column("last_observed_state", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("task_id", name=op.f("pk_proxmox_tasks")),
        sa.UniqueConstraint("upid", name=op.f("uq_proxmox_tasks_upid")),
    )
    op.create_table(
        "ssh_recordings",
        sa.Column("recording_ref", sa.String(length=128), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("command_hash", sa.String(length=64), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=False),
        sa.Column("stderr", sa.Text(), nullable=False),
        sa.Column("exit_status", sa.Integer(), nullable=True),
        sa.Column("redacted", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("recording_ref", name=op.f("pk_ssh_recordings")),
    )
    op.create_table(
        "siem_deliveries",
        sa.Column("delivery_id", sa.String(length=128), nullable=False),
        sa.Column("destination", sa.String(length=128), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("delivery_id", name=op.f("pk_siem_deliveries")),
    )
    op.create_table(
        "ssh_sessions",
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("actor_user_id", sa.String(length=128), nullable=False),
        sa.Column("actor_agent_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("cluster_id", sa.String(length=128), nullable=True),
        sa.Column("node_id", sa.String(length=128), nullable=False),
        sa.Column("interactive", sa.Boolean(), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recording_ref", sa.String(length=128), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("session_id", name=op.f("pk_ssh_sessions")),
    )


def downgrade() -> None:
    op.drop_table("ssh_sessions")
    op.drop_table("siem_deliveries")
    op.drop_table("ssh_recordings")
    op.drop_table("proxmox_tasks")
    op.drop_table("idempotency_records")
    op.drop_table("audit_events")
    op.drop_table("approval_requests")
