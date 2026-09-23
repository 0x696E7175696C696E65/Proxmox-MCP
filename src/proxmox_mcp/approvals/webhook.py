"""Signed HTTPS webhook dispatcher for approval mint notifications."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
from datetime import UTC, datetime
from typing import Protocol

from proxmox_mcp.security.egress import (
    https_request_no_redirect,
    validate_https_url_host,
)

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (0.5, 1.5, 3.0)
DEFAULT_MAX_SKEW_SECONDS = 300


class ApprovalWebhookSettings(Protocol):
    approval_webhook_url: str | None
    approval_webhook_secret: object | None


def validate_approval_webhook_url(
    url: str | None,
    *,
    allow_private_hosts: bool = False,
) -> str | None:
    if url is None or url == "":
        return None
    endpoint = validate_https_url_host(
        url,
        allow_private=allow_private_hosts,
        allow_public=True,
        resolve=True,
    )
    return endpoint.url


def sign_webhook_body(*, body: bytes, secret: str, timestamp: str) -> str:
    mac = hmac.new(
        secret.encode("utf-8"),
        msg=f"{timestamp}.".encode("utf-8") + body,
        digestmod=hashlib.sha256,
    )
    return mac.hexdigest()


def is_webhook_timestamp_fresh(
    timestamp: str,
    *,
    now: datetime | None = None,
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
) -> bool:
    effective_now = datetime.now(UTC) if now is None else now
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    delta = abs((effective_now - parsed).total_seconds())
    return delta <= max_skew_seconds


def verify_webhook_signature(
    *,
    body: bytes,
    secret: str,
    timestamp: str,
    signature: str,
    now: datetime | None = None,
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
) -> bool:
    if not is_webhook_timestamp_fresh(
        timestamp, now=now, max_skew_seconds=max_skew_seconds
    ):
        return False
    expected = sign_webhook_body(body=body, secret=secret, timestamp=timestamp)
    return hmac.compare_digest(expected, signature)


def build_approval_queued_payload(
    *,
    approval_request_id: str,
    operation: str,
    risk_level: str,
    expires_at: str,
    actor_user_id: str,
    actor_agent_id: str,
    nonce: str | None = None,
) -> dict[str, object]:
    return {
        "event": "approval.queued",
        "approval_request_id": approval_request_id,
        "operation": operation,
        "risk_level": risk_level,
        "expires_at": expires_at,
        "actor_user_id": actor_user_id,
        "actor_agent_id": actor_agent_id,
        "nonce": nonce or secrets.token_hex(16),
    }


def dispatch_signed_webhook_sync(
    *,
    url: str,
    secret: str,
    payload: dict[str, object],
    timeout_seconds: float = 5.0,
    allow_private_hosts: bool = False,
) -> tuple[bool, str | None]:
    if "nonce" not in payload:
        payload = {**payload, "nonce": secrets.token_hex(16)}
    timestamp = datetime.now(UTC).isoformat()
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = sign_webhook_body(body=body, secret=secret, timestamp=timestamp)
    last_error: str | None = None
    for attempt, delay in enumerate(BACKOFF_SECONDS[:MAX_ATTEMPTS], start=1):
        try:
            status, _ = https_request_no_redirect(
                url,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-Proxmox-MCP-Timestamp": timestamp,
                    "X-Proxmox-MCP-Signature": signature,
                    "X-Proxmox-MCP-Nonce": str(payload["nonce"]),
                    "User-Agent": "proxmox-mcp-approval-webhook/1",
                },
                data=body,
                timeout_seconds=timeout_seconds,
                allow_private=allow_private_hosts,
                allow_public=True,
            )
            if 200 <= status < 300:
                return True, None
            last_error = f"http_{status}"
        except ValueError as exc:
            return False, f"url_policy:{exc}"
        except Exception as exc:  # noqa: BLE001
            last_error = type(exc).__name__
        if attempt < MAX_ATTEMPTS:
            import time

            time.sleep(delay)
    return False, last_error


async def maybe_dispatch_approval_queued(
    *,
    settings: ApprovalWebhookSettings,
    payload: dict[str, object],
    audit_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    """Dispatch webhook if configured. Returns delivery metadata for audit."""
    url = getattr(settings, "approval_webhook_url", None)
    secret_obj = getattr(settings, "approval_webhook_secret", None)
    meta: dict[str, object] = {"webhook_attempted": False}
    if audit_metadata is not None:
        meta.update(audit_metadata)
    if not url or secret_obj is None:
        return meta
    allow_private = bool(getattr(settings, "webhook_allow_private_hosts", False))
    try:
        validated = validate_approval_webhook_url(str(url), allow_private_hosts=allow_private)
    except ValueError as exc:
        meta.update({"webhook_attempted": True, "webhook_ok": False, "webhook_error": str(exc)})
        return meta
    if validated is None:
        return meta
    secret = (
        secret_obj.get_secret_value()
        if hasattr(secret_obj, "get_secret_value")
        else str(secret_obj)
    )
    if not secret:
        meta.update(
            {
                "webhook_attempted": True,
                "webhook_ok": False,
                "webhook_error": "missing_secret",
            }
        )
        return meta

    ok, error = await asyncio.to_thread(
        dispatch_signed_webhook_sync,
        url=validated,
        secret=secret,
        payload=payload,
        allow_private_hosts=allow_private,
    )
    meta.update(
        {
            "webhook_attempted": True,
            "webhook_ok": ok,
            "webhook_error": error,
            "webhook_dead_letter": not ok,
        }
    )
    if not ok:
        logger.warning(
            "approval webhook delivery failed approval_request_id=%s error=%s",
            payload.get("approval_request_id"),
            error,
        )
    return meta
