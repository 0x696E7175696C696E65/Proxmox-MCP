from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from proxmox_mcp.persistence.models.base import Base


class ApprovalDecisionRecord(Base):
    __tablename__ = "approval_decisions"

    decision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    approval_request_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("approval_requests.approval_request_id", name="fk_approval_decisions_req"),
        nullable=False,
    )
    approver_user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    approver_username: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    step_up_audit_id: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
