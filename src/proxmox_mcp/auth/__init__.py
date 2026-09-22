from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from inspect import isawaitable
from typing import Literal, Protocol, cast
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

AuthMethod = Literal[
    "service_token",
    "oidc_jwt",
    "mtls_client_certificate",
    "workload_identity",
]
SessionStatus = Literal["active", "expired", "revoked"]


@dataclass(frozen=True, slots=True)
class ActorIdentity:
    user_id: str
    agent_id: str
    tenant_id: str | None = None


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    session_id: str
    identity: ActorIdentity
    auth_method: AuthMethod
    status: SessionStatus
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ClientCertificateIdentity:
    subject: str
    fingerprint_sha256: str
    san_dns: tuple[str, ...] = ()


class OidcClaimsVerifier(Protocol):
    def verify(
        self,
        token: str,
        *,
        issuer: str,
        audience: str,
        now: datetime,
    ) -> dict[str, object]: ...


class WorkloadIdentityReplayCache(Protocol):
    def consume(self, jti: str, *, expires_at: datetime, now: datetime) -> bool: ...


class RedisWorkloadIdentityReplayClient(Protocol):
    def set(
        self,
        name: str,
        value: str,
        *,
        nx: bool,
        ex: int,
    ) -> object: ...


class InMemoryWorkloadIdentityReplayCache:
    def __init__(self) -> None:
        self._seen_jtis: dict[str, datetime] = {}

    def consume(self, jti: str, *, expires_at: datetime, now: datetime) -> bool:
        self._seen_jtis = {
            cached_jti: cached_expiry
            for cached_jti, cached_expiry in self._seen_jtis.items()
            if cached_expiry > now
        }
        if jti in self._seen_jtis:
            return False

        self._seen_jtis[jti] = expires_at
        return True


class RedisWorkloadIdentityReplayCache:
    def __init__(
        self,
        client: RedisWorkloadIdentityReplayClient,
        *,
        namespace: str = "proxmox_mcp:workload_identity:jti",
    ) -> None:
        self._client = client
        self._namespace = namespace

    def consume(self, jti: str, *, expires_at: datetime, now: datetime) -> bool:
        ttl_seconds = max(1, int((expires_at - now).total_seconds()))
        result = self._client.set(
            f"{self._namespace}:{jti}",
            "consumed",
            nx=True,
            ex=ttl_seconds,
        )
        if isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise TypeError("RedisWorkloadIdentityReplayCache requires a synchronous Redis client")
        return result is True or result == "OK"


class StaticJwksOidcClaimsVerifier:
    def __init__(self, jwks: Mapping[str, object]) -> None:
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise ValueError("JWKS must contain a keys array")
        typed_keys = cast(list[object], keys)
        self._keys = tuple(
            _rsa_key_from_jwk(cast(Mapping[object, object], key))
            for key in typed_keys
            if isinstance(key, Mapping)
        )

    def verify(
        self,
        token: str,
        *,
        issuer: str,
        audience: str,
        now: datetime,
    ) -> dict[str, object]:
        header, claims, signing_input, signature = _decode_jwt(token)
        if header.get("alg") != "RS256":
            raise ValueError("Unsupported OIDC JWT algorithm")

        public_key = self._select_key(header)
        try:
            public_key.verify(
                signature,
                signing_input.encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise ValueError("Invalid OIDC JWT signature") from exc
        _validate_oidc_claims(claims, issuer=issuer, audience=audience, now=now)
        return claims

    def _select_key(self, header: dict[str, object]) -> rsa.RSAPublicKey:
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise ValueError("OIDC JWT is missing kid")

        for key_id, public_key in self._keys:
            if key_id == kid:
                return public_key

        raise ValueError("No matching OIDC JWKS key")


class ServiceTokenAuthenticator:
    def __init__(
        self,
        *,
        expected_token: str | None = None,
        expected_token_sha256: str | None = None,
        session_ttl: timedelta = timedelta(hours=1),
    ) -> None:
        self._expected_token = expected_token
        self._expected_token_sha256 = expected_token_sha256
        self._session_ttl = session_ttl

    def authenticate(
        self,
        presented_token: str,
        *,
        identity: ActorIdentity,
        now: datetime | None = None,
    ) -> AuthenticatedSession | None:
        if not self._token_matches(presented_token):
            return None

        issued_at = datetime.now(UTC) if now is None else now
        return AuthenticatedSession(
            session_id=f"sess_{uuid4().hex}",
            identity=identity,
            auth_method="service_token",
            status="active",
            issued_at=issued_at,
            expires_at=issued_at + self._session_ttl,
        )

    @staticmethod
    def sha256_token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _token_matches(self, presented_token: str) -> bool:
        if self._expected_token is not None:
            return hmac.compare_digest(presented_token, self._expected_token)

        if self._expected_token_sha256 is not None:
            presented_hash = self.sha256_token_hash(presented_token)
            return hmac.compare_digest(presented_hash, self._expected_token_sha256)

        return False


class OidcJwtAuthenticator:
    def __init__(
        self,
        *,
        verifier: OidcClaimsVerifier,
        issuer: str,
        audience: str,
        session_ttl: timedelta = timedelta(hours=1),
    ) -> None:
        self._verifier = verifier
        self._issuer = issuer
        self._audience = audience
        self._session_ttl = session_ttl

    def authenticate(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> AuthenticatedSession | None:
        issued_at = datetime.now(UTC) if now is None else now
        try:
            claims = self._verifier.verify(
                token,
                issuer=self._issuer,
                audience=self._audience,
                now=issued_at,
            )
            identity = _identity_from_claims(claims)
        except (TypeError, ValueError):
            return None

        return _session(
            identity=identity,
            auth_method="oidc_jwt",
            issued_at=issued_at,
            ttl=self._session_ttl,
        )


class MtlsClientCertificateAuthenticator:
    def __init__(
        self,
        *,
        trusted_fingerprints: dict[str, ActorIdentity] | None = None,
        trusted_subjects: dict[str, ActorIdentity] | None = None,
        session_ttl: timedelta = timedelta(hours=1),
    ) -> None:
        self._trusted_fingerprints = {
            _normalize_fingerprint(fingerprint): identity
            for fingerprint, identity in (trusted_fingerprints or {}).items()
        }
        self._trusted_subjects = dict(trusted_subjects or {})
        self._session_ttl = session_ttl

    def authenticate(
        self,
        certificate: ClientCertificateIdentity,
        *,
        now: datetime | None = None,
    ) -> AuthenticatedSession | None:
        identity = self._trusted_fingerprints.get(
            _normalize_fingerprint(certificate.fingerprint_sha256)
        )
        if identity is None:
            identity = self._trusted_subjects.get(certificate.subject)
        if identity is None:
            return None

        issued_at = datetime.now(UTC) if now is None else now
        return _session(
            identity=identity,
            auth_method="mtls_client_certificate",
            issued_at=issued_at,
            ttl=self._session_ttl,
        )


class SignedWorkloadIdentityAuthenticator:
    def __init__(
        self,
        *,
        shared_secret: str,
        audience: str,
        session_ttl: timedelta = timedelta(hours=1),
        replay_cache: WorkloadIdentityReplayCache | None = None,
    ) -> None:
        self._shared_secret = shared_secret.encode("utf-8")
        self._audience = audience
        self._session_ttl = session_ttl
        self._replay_cache = replay_cache or InMemoryWorkloadIdentityReplayCache()

    def authenticate(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> AuthenticatedSession | None:
        issued_at = datetime.now(UTC) if now is None else now
        try:
            claims = self._verify_signed_claims(token)
            identity = _identity_from_claims(claims)
            jti, expires_at = self._validate_workload_claims(claims, now=issued_at)
        except (TypeError, ValueError):
            return None

        if not self._replay_cache.consume(jti, expires_at=expires_at, now=issued_at):
            return None
        return _session(
            identity=identity,
            auth_method="workload_identity",
            issued_at=issued_at,
            ttl=self._session_ttl,
        )

    def sign_test_token(self, claims: dict[str, object]) -> str:
        payload = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signature = _b64url_encode(
            hmac.new(self._shared_secret, payload.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{payload}.{signature}"

    def _verify_signed_claims(self, token: str) -> dict[str, object]:
        payload_part, signature_part = token.split(".", 1)
        expected_signature = _b64url_encode(
            hmac.new(self._shared_secret, payload_part.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature_part, expected_signature):
            raise ValueError("Invalid workload identity signature")

        payload = json.loads(_b64url_decode(payload_part))
        if not isinstance(payload, dict):
            raise ValueError("Malformed workload identity payload")
        return cast(dict[str, object], payload)

    def _validate_workload_claims(
        self, claims: dict[str, object], *, now: datetime
    ) -> tuple[str, datetime]:
        if claims.get("aud") != self._audience:
            raise ValueError("Invalid workload identity audience")

        exp = claims.get("exp")
        if not isinstance(exp, int | float):
            raise ValueError("Expired workload identity")
        expires_at = datetime.fromtimestamp(exp, UTC)
        if expires_at <= now:
            raise ValueError("Expired workload identity")

        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise ValueError("Invalid workload identity nonce")

        return jti, expires_at


def _session(
    *,
    identity: ActorIdentity,
    auth_method: AuthMethod,
    issued_at: datetime,
    ttl: timedelta,
) -> AuthenticatedSession:
    return AuthenticatedSession(
        session_id=f"sess_{uuid4().hex}",
        identity=identity,
        auth_method=auth_method,
        status="active",
        issued_at=issued_at,
        expires_at=issued_at + ttl,
    )


def _identity_from_claims(claims: dict[str, object]) -> ActorIdentity:
    user_id = claims.get("sub")
    agent_id = claims.get("agent_id") or claims.get("azp") or claims.get("client_id")
    tenant_id = claims.get("tenant_id")
    if not isinstance(user_id, str) or not user_id:
        raise ValueError("Missing subject claim")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("Missing agent identity claim")
    if tenant_id is not None and not isinstance(tenant_id, str):
        raise ValueError("Invalid tenant claim")

    return ActorIdentity(user_id=user_id, agent_id=agent_id, tenant_id=tenant_id)


def _normalize_fingerprint(fingerprint: str) -> str:
    return fingerprint.replace(":", "").lower()


def _b64url_encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _b64url_decode(payload: str) -> bytes:
    padding = "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload + padding)


def _rsa_key_from_jwk(jwk: Mapping[object, object]) -> tuple[str, rsa.RSAPublicKey]:
    if jwk.get("kty") != "RSA":
        raise ValueError("Only RSA JWKS keys are supported")
    kid = jwk.get("kid")
    modulus = jwk.get("n")
    exponent = jwk.get("e")
    if not isinstance(kid, str) or not isinstance(modulus, str) or not isinstance(exponent, str):
        raise ValueError("Malformed RSA JWKS key")

    public_numbers = rsa.RSAPublicNumbers(
        e=int.from_bytes(_b64url_decode(exponent), "big"),
        n=int.from_bytes(_b64url_decode(modulus), "big"),
    )
    return kid, public_numbers.public_key()


def _decode_jwt(
    token: str,
) -> tuple[dict[str, object], dict[str, object], str, bytes]:
    header_part, payload_part, signature_part = token.split(".", 2)
    header = json.loads(_b64url_decode(header_part))
    claims = json.loads(_b64url_decode(payload_part))
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("Malformed OIDC JWT")
    return (
        cast(dict[str, object], header),
        cast(dict[str, object], claims),
        f"{header_part}.{payload_part}",
        _b64url_decode(signature_part),
    )


def _validate_oidc_claims(
    claims: dict[str, object],
    *,
    issuer: str,
    audience: str,
    now: datetime,
) -> None:
    if claims.get("iss") != issuer:
        raise ValueError("Invalid OIDC issuer")
    if not _audience_matches(claims.get("aud"), audience):
        raise ValueError("Invalid OIDC audience")

    exp = claims.get("exp")
    if not isinstance(exp, int | float) or datetime.fromtimestamp(exp, UTC) <= now:
        raise ValueError("Expired OIDC token")

    nbf = claims.get("nbf")
    if isinstance(nbf, int | float) and datetime.fromtimestamp(nbf, UTC) > now:
        raise ValueError("OIDC token is not valid yet")


def _audience_matches(claim_audience: object, expected: str) -> bool:
    if isinstance(claim_audience, str):
        return claim_audience == expected
    if isinstance(claim_audience, list):
        audiences = cast(list[object], claim_audience)
        return expected in {value for value in audiences if isinstance(value, str)}
    return False
