from __future__ import annotations

from contextvars import ContextVar, Token

from proxmox_mcp.admin.auth.providers import AdminSession

_admin_session: ContextVar[AdminSession | None] = ContextVar("admin_session", default=None)


def set_admin_session(session: AdminSession | None) -> Token[AdminSession | None]:
    return _admin_session.set(session)


def reset_admin_session(token: Token[AdminSession | None]) -> None:
    _admin_session.reset(token)


def get_admin_session() -> AdminSession | None:
    return _admin_session.get()
