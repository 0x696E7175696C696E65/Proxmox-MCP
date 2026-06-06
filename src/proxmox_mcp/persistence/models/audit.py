from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from proxmox_mcp.persistence.models.base import Base


class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(128))
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    operation: Mapped[str] = mapped_column(String(256), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False)
    cluster_id: Mapped[str | None] = mapped_column(String(128))
    node_id: Mapped[str | None] = mapped_column(String(128))
    result_status: Mapped[str] = mapped_column(String(32), nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(128))
    target_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    event_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
