from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import SecretStr

REDACTED_VALUE = "**********"

_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cipassword",
    "cookie",
    "credential",
    "csrf",
    "key_file",
    "password",
    "private_key",
    "secret",
    "session_token",
    "set_cookie",
    "sshkeys",
    "ticket",
    "token",
)

# Ambiguous tokens matched only as whole underscore-separated segments.
_SENSITIVE_KEY_TOKENS = frozenset({"auth", "key"})

# One-time agent capabilities that may survive the MCP *error-details* boundary only.
# Never pass these through audit / SSE / SIEM / webhook sanitization.
_AGENT_CAPABILITY_PASSTHROUGH_KEYS = frozenset({"approval_resume_secret"})


def sanitize_for_security_boundary(
    value: object,
    *,
    allow_agent_capabilities: bool = False,
) -> object:
    if isinstance(value, SecretStr):
        return REDACTED_VALUE

    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}
        mapping = cast(Mapping[object, object], value)
        for key, item in mapping.items():
            key_text = str(key)
            if _is_sensitive_key(key_text, allow_agent_capabilities=allow_agent_capabilities):
                sanitized[key_text] = REDACTED_VALUE
            else:
                sanitized[key_text] = sanitize_for_security_boundary(
                    item,
                    allow_agent_capabilities=allow_agent_capabilities,
                )
        return sanitized

    if isinstance(value, tuple):
        items = cast(tuple[object, ...], value)
        return tuple(
            sanitize_for_security_boundary(
                item,
                allow_agent_capabilities=allow_agent_capabilities,
            )
            for item in items
        )

    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        items = cast(Sequence[object], value)
        return [
            sanitize_for_security_boundary(
                item,
                allow_agent_capabilities=allow_agent_capabilities,
            )
            for item in items
        ]

    return value


def _is_sensitive_key(key: str, *, allow_agent_capabilities: bool = False) -> bool:
    normalized = key.lower().replace("-", "_")
    if allow_agent_capabilities and normalized in _AGENT_CAPABILITY_PASSTHROUGH_KEYS:
        return False
    if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
        return True
    tokens = frozenset(normalized.split("_"))
    return bool(tokens & _SENSITIVE_KEY_TOKENS)
