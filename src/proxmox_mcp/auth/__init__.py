from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

AuthMethod = Literal["service_token"]
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
