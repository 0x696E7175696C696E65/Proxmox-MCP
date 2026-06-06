from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import SecretStr

REDACTED_VALUE = "**********"

_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "auth",
    "credential",
    "key_file",
    "password",
    "private_key",
    "secret",
    "token",
)


def sanitize_for_security_boundary(value: object) -> object:
    if isinstance(value, SecretStr):
        return REDACTED_VALUE

    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}
        mapping = cast(Mapping[object, object], value)
        for key, item in mapping.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                sanitized[key_text] = REDACTED_VALUE
            else:
                sanitized[key_text] = sanitize_for_security_boundary(item)
        return sanitized

    if isinstance(value, tuple):
        items = cast(tuple[object, ...], value)
        return tuple(sanitize_for_security_boundary(item) for item in items)

    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        items = cast(Sequence[object], value)
        return [sanitize_for_security_boundary(item) for item in items]

    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)
