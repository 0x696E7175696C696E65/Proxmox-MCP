from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from proxmox_mcp.auth import (
    ActorIdentity,
    ClientCertificateIdentity,
    InMemoryWorkloadIdentityReplayCache,
    MtlsClientCertificateAuthenticator,
    OidcClaimsVerifier,
    OidcJwtAuthenticator,
    RedisWorkloadIdentityReplayCache,
    ServiceTokenAuthenticator,
    SignedWorkloadIdentityAuthenticator,
    StaticJwksOidcClaimsVerifier,
)

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


def test_oidc_authenticator_maps_verified_claims_to_actor() -> None:
    class FakeVerifier(OidcClaimsVerifier):
        def verify(
            self, token: str, *, issuer: str, audience: str, now: datetime
        ) -> dict[str, object]:
            assert token == "j" + "wt"
            assert issuer == "https://issuer.example"
            assert audience == "proxmox-mcp"
            assert now == datetime(2026, 1, 1, tzinfo=UTC)
            return {
                "sub": "user_1",
                "azp": "agent_1",
                "tenant_id": "tenant_1",
            }

    authenticator = OidcJwtAuthenticator(
        verifier=FakeVerifier(),
        issuer="https://issuer.example",
        audience="proxmox-mcp",
    )

    session = authenticator.authenticate("jwt", now=datetime(2026, 1, 1, tzinfo=UTC))

    assert session is not None
    assert session.auth_method == "oidc_jwt"
    assert session.identity == ActorIdentity(
        user_id="user_1",
        agent_id="agent_1",
        tenant_id="tenant_1",
    )


def test_oidc_authenticator_fails_closed_for_invalid_issuer_or_audience() -> None:
    class FailingVerifier(OidcClaimsVerifier):
        def verify(
            self, token: str, *, issuer: str, audience: str, now: datetime
        ) -> dict[str, object]:
            _ = token, issuer, audience, now
            raise ValueError("issuer mismatch")

    authenticator = OidcJwtAuthenticator(
        verifier=FailingVerifier(),
        issuer="https://issuer.example",
        audience="proxmox-mcp",
    )

    assert authenticator.authenticate("jwt") is None


def test_static_jwks_oidc_verifier_validates_issuer_audience_and_signature() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key",
                "alg": "RS256",
                "use": "sig",
                "n": _int_to_b64url(public_numbers.n),
                "e": _int_to_b64url(public_numbers.e),
            }
        ]
    }
    now = datetime(2026, 1, 1, tzinfo=UTC)
    token = _signed_rs256_jwt(
        key,
        kid="test-key",
        claims={
            "iss": "https://issuer.example",
            "aud": "proxmox-mcp",
            "sub": "user_1",
            "agent_id": "agent_1",
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
    )

    claims = StaticJwksOidcClaimsVerifier(jwks).verify(
        token,
        issuer="https://issuer.example",
        audience="proxmox-mcp",
        now=now,
    )

    assert claims["sub"] == "user_1"
    with pytest.raises(ValueError, match="audience"):
        StaticJwksOidcClaimsVerifier(jwks).verify(
            token,
            issuer="https://issuer.example",
            audience="other",
            now=now,
        )


def test_mtls_authenticator_maps_trusted_certificate_fingerprint() -> None:
    authenticator = MtlsClientCertificateAuthenticator(
        trusted_fingerprints={"abc123": ActorIdentity(user_id="user_1", agent_id="agent_1")}
    )

    session = authenticator.authenticate(
        ClientCertificateIdentity(subject="CN=agent", fingerprint_sha256="abc123")
    )

    assert session is not None
    assert session.auth_method == "mtls_client_certificate"
    assert session.identity.user_id == "user_1"


def test_mtls_authenticator_denies_untrusted_certificate() -> None:
    authenticator = MtlsClientCertificateAuthenticator(
        trusted_fingerprints={"abc123": ActorIdentity(user_id="user_1", agent_id="agent_1")}
    )

    assert (
        authenticator.authenticate(
            ClientCertificateIdentity(subject="CN=agent", fingerprint_sha256="wrong")
        )
        is None
    )


def test_signed_workload_identity_rejects_replay_and_wrong_audience() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    authenticator = SignedWorkloadIdentityAuthenticator(
        shared_secret="signing-" + "key",
        audience="proxmox-mcp",
    )
    token = authenticator.sign_test_token(
        {
            "sub": "user_1",
            "agent_id": "agent_1",
            "aud": "proxmox-mcp",
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jti": "nonce-1",
        }
    )

    first = authenticator.authenticate(token, now=now)
    replay = authenticator.authenticate(token, now=now)
    wrong_audience = authenticator.sign_test_token(
        {
            "sub": "user_1",
            "agent_id": "agent_1",
            "aud": "other",
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jti": "nonce-2",
        }
    )

    assert first is not None
    assert first.auth_method == "workload_identity"
    assert replay is None
    assert authenticator.authenticate(wrong_audience, now=now) is None


def test_signed_workload_identity_replay_cache_can_be_shared_across_replicas() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    replay_cache = InMemoryWorkloadIdentityReplayCache()
    first_replica = SignedWorkloadIdentityAuthenticator(
        shared_secret="signing-" + "key",
        audience="proxmox-mcp",
        replay_cache=replay_cache,
    )
    second_replica = SignedWorkloadIdentityAuthenticator(
        shared_secret="signing-" + "key",
        audience="proxmox-mcp",
        replay_cache=replay_cache,
    )
    token = first_replica.sign_test_token(
        {
            "sub": "user_1",
            "agent_id": "agent_1",
            "aud": "proxmox-mcp",
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jti": "nonce-cross-replica",
        }
    )

    assert first_replica.authenticate(token, now=now) is not None
    assert second_replica.authenticate(token, now=now) is None


def test_redis_workload_identity_replay_cache_uses_atomic_set_nx() -> None:
    class FakeRedisClient:
        def __init__(self) -> None:
            self.values: dict[str, str] = {}
            self.expiries: dict[str, int] = {}

        def set(self, name: str, value: str, *, nx: bool, ex: int) -> object:
            assert nx is True
            if name in self.values:
                return None
            self.values[name] = value
            self.expiries[name] = ex
            return True

    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = FakeRedisClient()
    cache = RedisWorkloadIdentityReplayCache(client)

    assert cache.consume("nonce-1", expires_at=now + timedelta(seconds=30), now=now) is True
    assert cache.consume("nonce-1", expires_at=now + timedelta(seconds=30), now=now) is False
    assert client.expiries["proxmox_mcp:workload_identity:jti:nonce-1"] == 30


def test_redis_workload_identity_replay_cache_rejects_async_client() -> None:
    class AsyncRedisLikeClient:
        async def set(self, name: str, value: str, *, nx: bool, ex: int) -> object:
            _ = name, value, nx, ex
            return True

    now = datetime(2026, 1, 1, tzinfo=UTC)
    cache = RedisWorkloadIdentityReplayCache(AsyncRedisLikeClient())  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="synchronous Redis client"):
        cache.consume("nonce-1", expires_at=now + timedelta(seconds=30), now=now)


def _signed_rs256_jwt(
    key: rsa.RSAPrivateKey,
    *,
    kid: str,
    claims: dict[str, object],
) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    signing_input = ".".join(
        [
            _json_b64url(header),
            _json_b64url(claims),
        ]
    )
    signature = key.sign(
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{signing_input}.{_bytes_to_b64url(signature)}"


def _json_b64url(payload: Mapping[str, object]) -> str:
    return _bytes_to_b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def _int_to_b64url(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    return _bytes_to_b64url(value.to_bytes(byte_length, "big"))


def _bytes_to_b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
