from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from proxmox_mcp.persistence.models.base import Base


class CapabilityRoleRecord(Base):
    __tablename__ = "capability_roles"

    role_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    base_template: Mapped[str | None] = mapped_column(String(64))
    granted_tools_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    denied_tools_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    permission_seeds_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AdminUserRecord(Base):
    __tablename__ = "admin_users"

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="admin")
    capability_role_id: Mapped[str | None] = mapped_column(
        String(128),
        ForeignKey("capability_roles.role_id", name="fk_admin_users_capability_role_id"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


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
