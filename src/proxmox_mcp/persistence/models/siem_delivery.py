from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from proxmox_mcp.persistence.models.base import Base


class SiemDeliveryRecord(Base):
    __tablename__ = "siem_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    destination: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    next_retry_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
