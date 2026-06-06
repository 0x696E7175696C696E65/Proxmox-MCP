from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from proxmox_mcp.persistence.models.base import Base


class ApprovalRecord(Base):
    __tablename__ = "approval_requests"

    approval_request_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    operation: Mapped[str] = mapped_column(String(256), nullable=False)
    target_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approval_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    actor_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_tenant_id: Mapped[str | None] = mapped_column(String(128))
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
