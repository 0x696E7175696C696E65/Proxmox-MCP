from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from proxmox_mcp.persistence.models.base import Base


class AdminUserRecord(Base):
    __tablename__ = "admin_users"

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="admin")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AdminSessionRecord(Base):
    __tablename__ = "admin_sessions"

    session_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("admin_users.user_id", name="fk_admin_sessions_user_id"),
        nullable=False,
    )
    csrf_token: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
