from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from proxmox_mcp.persistence.models.base import Base


class SshSessionRecordModel(Base):
    __tablename__ = "ssh_sessions"

    session_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(128))
    cluster_id: Mapped[str | None] = mapped_column(String(128))
    node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    interactive: Mapped[bool] = mapped_column(Boolean, nullable=False)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recording_ref: Mapped[str | None] = mapped_column(String(128))
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
