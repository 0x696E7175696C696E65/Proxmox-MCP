from __future__ import annotations

from proxmox_mcp.admin.auth.context import get_admin_session, reset_admin_session, set_admin_session
from proxmox_mcp.admin.auth.passwords import hash_password, verify_password
from proxmox_mcp.admin.auth.providers import (
    CSRF_HEADER,
    SESSION_COOKIE,
    AdminIdentity,
    AdminIdentityProvider,
    AdminSession,
    LocalPasswordProvider,
)

__all__ = [
    "CSRF_HEADER",
    "SESSION_COOKIE",
    "AdminIdentity",
    "AdminIdentityProvider",
    "AdminSession",
    "LocalPasswordProvider",
    "get_admin_session",
    "hash_password",
    "reset_admin_session",
    "set_admin_session",
    "verify_password",
]
