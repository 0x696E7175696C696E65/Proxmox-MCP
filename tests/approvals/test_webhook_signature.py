from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from proxmox_mcp.approvals.webhook import (
    build_approval_queued_payload,
    sign_webhook_body,
    validate_approval_webhook_url,
)


def test_webhook_url_requires_https() -> None:
    assert validate_approval_webhook_url(None) is None
    with pytest.raises(ValueError, match="https"):
        validate_approval_webhook_url("http://example.com/hook")
    # Public hostname resolves; may fail DNS in offline CI — allow either success or DNS error
    try:
        assert validate_approval_webhook_url("https://example.com/hook") == "https://example.com/hook"
    except ValueError as exc:
        assert "DNS" in str(exc) or "resolution" in str(exc).lower()


def test_webhook_rejects_private_literals() -> None:
    with pytest.raises(ValueError):
        validate_approval_webhook_url("https://127.0.0.1/hook")
    with pytest.raises(ValueError):
        validate_approval_webhook_url("https://169.254.169.254/latest")


def test_webhook_signature_roundtrip() -> None:
    payload = build_approval_queued_payload(
        approval_request_id="req-1",
        operation="vm.delete",
        risk_level="critical",
        expires_at="2026-01-01T00:00:00+00:00",
        actor_user_id="u1",
        actor_agent_id="a1",
    )
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = "2026-01-01T00:00:00+00:00"
    secret = "s" * 32
    signature = sign_webhook_body(body=body, secret=secret, timestamp=timestamp)
    expected = hmac.new(
        secret.encode("utf-8"),
        msg=f"{timestamp}.".encode("utf-8") + body,
        digestmod=hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(signature, expected)
