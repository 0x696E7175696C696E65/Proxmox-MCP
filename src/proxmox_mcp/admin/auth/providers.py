from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.admin.auth.passwords import (
    hash_password,
    verify_password,
    verify_password_or_dummy,
)
from proxmox_mcp.persistence.models.admin import AdminSessionRecord, AdminUserRecord

SESSION_IDLE_TTL = timedelta(minutes=30)
SESSION_ABSOLUTE_TTL = timedelta(hours=8)
SESSION_TTL = SESSION_ABSOLUTE_TTL
SESSION_COOKIE = "proxmox_mcp_admin_session"
CSRF_HEADER = "x-csrf-token"

AdminRole = Literal["admin", "operator"]


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


@dataclass(frozen=True, slots=True)
class AdminIdentity:
    user_id: str
    username: str
    role: AdminRole = "admin"


@dataclass(frozen=True, slots=True)
class AdminSession:
    session_id: str
    csrf_token: str
    identity: AdminIdentity
    expires_at: datetime


class AdminIdentityProvider(Protocol):
    async def authenticate(self, username: str, password: str) -> AdminIdentity | None: ...

    async def create_session(self, identity: AdminIdentity) -> AdminSession: ...

    async def get_session(self, session_id: str) -> AdminSession | None: ...

    async def revoke_session(self, session_id: str) -> None: ...

    async def ensure_bootstrap_user(self, username: str, password: str) -> None: ...

    async def verify_user_password(self, user_id: str, password: str) -> bool: ...


class LocalPasswordProvider:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def authenticate(self, username: str, password: str) -> AdminIdentity | None:
        async with self._session_factory() as session:
            record = (
                await session.scalars(
                    select(AdminUserRecord).where(AdminUserRecord.username == username)
                )
            ).first()
            password_hash = None if record is None else record.password_hash
            if not verify_password_or_dummy(password_hash, password):
                return None
            assert record is not None
            record.last_login_at = datetime.now(UTC)
            await session.commit()
            role = _normalize_role(getattr(record, "role", None))
            return AdminIdentity(user_id=record.user_id, username=record.username, role=role)

    async def create_session(self, identity: AdminIdentity) -> AdminSession:
        now = datetime.now(UTC)
        session_id = _new_id("adminsess")
        csrf_token = uuid4().hex
        expires_at = now + SESSION_IDLE_TTL
        async with self._session_factory() as session:
            session.add(
                AdminSessionRecord(
                    session_id=session_id,
                    user_id=identity.user_id,
                    csrf_token=csrf_token,
                    created_at=now,
                    expires_at=expires_at,
                    revoked_at=None,
                )
            )
            await session.commit()
        return AdminSession(
            session_id=session_id,
            csrf_token=csrf_token,
            identity=identity,
            expires_at=expires_at,
        )

    async def get_session(self, session_id: str) -> AdminSession | None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            record = await session.get(AdminSessionRecord, session_id)
            if record is None or record.revoked_at is not None:
                return None
            created_at = record.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            if record.expires_at <= now or created_at + SESSION_ABSOLUTE_TTL <= now:
                return None
            user = await session.get(AdminUserRecord, record.user_id)
            if user is None:
                return None
            record.expires_at = now + SESSION_IDLE_TTL
            await session.commit()
            return AdminSession(
                session_id=record.session_id,
                csrf_token=record.csrf_token,
                identity=AdminIdentity(
                    user_id=user.user_id,
                    username=user.username,
                    role=_normalize_role(getattr(user, "role", None)),
                ),
                expires_at=record.expires_at,
            )

    async def revoke_session(self, session_id: str) -> None:
        async with self._session_factory() as session:
            record = await session.get(AdminSessionRecord, session_id)
            if record is None:
                return
            record.revoked_at = datetime.now(UTC)
            await session.commit()

    async def verify_user_password(self, user_id: str, password: str) -> bool:
        async with self._session_factory() as session:
            record = await session.get(AdminUserRecord, user_id)
            password_hash = None if record is None else record.password_hash
            return verify_password_or_dummy(password_hash, password)

    async def ensure_bootstrap_user(self, username: str, password: str) -> None:
        from sqlalchemy.exc import ProgrammingError

        try:
            async with self._session_factory() as session:
                existing = (
                    await session.scalars(
                        select(AdminUserRecord).where(AdminUserRecord.username == username)
                    )
                ).first()
                if existing is not None:
                    return
                session.add(
                    AdminUserRecord(
                        user_id=_new_id("adminuser"),
                        username=username,
                        password_hash=hash_password(password),
                        role="admin",
                        created_at=datetime.now(UTC),
                        last_login_at=None,
                    )
                )
                await session.commit()
        except ProgrammingError as exc:
            raise RuntimeError(
                "Admin tables are missing. Run `proxmox-mcp migrate` before enabling admin auth."
            ) from exc


def _normalize_role(value: object) -> AdminRole:
    if value == "operator":
        return "operator"
    return "admin"
