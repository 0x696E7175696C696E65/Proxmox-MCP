from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_HASHER = PasswordHasher()
# Fixed dummy hash so missing-user logins still pay Argon2 verify cost.
_DUMMY_PASSWORD_HASH = _HASHER.hash("proxmox-mcp-dummy-password-not-used")


def hash_password(password: str) -> str:
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _HASHER.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def verify_password_or_dummy(password_hash: str | None, password: str) -> bool:
    """Constant-ish timing verify; uses a dummy hash when the user is missing."""
    if password_hash is None:
        verify_password(_DUMMY_PASSWORD_HASH, password)
        return False
    return verify_password(password_hash, password)
