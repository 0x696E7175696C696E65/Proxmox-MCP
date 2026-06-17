from __future__ import annotations

import contextvars

from proxmox_mcp.auth import AuthenticatedSession

_request_session: contextvars.ContextVar[AuthenticatedSession | None] = contextvars.ContextVar(
    "mcp_request_session",
    default=None,
)


def get_request_session() -> AuthenticatedSession | None:
    return _request_session.get()


def set_request_session(
    session: AuthenticatedSession | None,
) -> contextvars.Token[AuthenticatedSession | None]:
    return _request_session.set(session)


def reset_request_session(token: contextvars.Token[AuthenticatedSession | None]) -> None:
    _request_session.reset(token)
