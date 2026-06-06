from __future__ import annotations

from datetime import UTC, datetime, timedelta

from proxmox_mcp.auth import ActorIdentity, ServiceTokenAuthenticator

CONFIGURED_VALUE = "secret-token"


def test_service_token_authenticator_creates_active_session_for_valid_token() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    identity = ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1")
    authenticator = ServiceTokenAuthenticator(
        expected_token=CONFIGURED_VALUE,
        session_ttl=timedelta(minutes=15),
    )

    session = authenticator.authenticate(CONFIGURED_VALUE, identity=identity, now=now)

    assert session is not None
    assert session.identity == identity
    assert session.auth_method == "service_token"
    assert session.status == "active"
    assert session.issued_at == now
    assert session.expires_at == now + timedelta(minutes=15)


def test_service_token_authenticator_rejects_invalid_token() -> None:
    authenticator = ServiceTokenAuthenticator(expected_token=CONFIGURED_VALUE)

    session = authenticator.authenticate(
        "wrong-token",
        identity=ActorIdentity(user_id="user_1", agent_id="agent_1"),
    )

    assert session is None


def test_service_token_authenticator_accepts_sha256_token_hash() -> None:
    identity = ActorIdentity(user_id="user_1", agent_id="agent_1")
    expected_hash = ServiceTokenAuthenticator.sha256_token_hash(CONFIGURED_VALUE)
    authenticator = ServiceTokenAuthenticator(expected_token_sha256=expected_hash)

    session = authenticator.authenticate(CONFIGURED_VALUE, identity=identity)

    assert session is not None
    assert session.identity.user_id == "user_1"
