from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import hmac

from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession, ServiceTokenAuthenticator
from proxmox_mcp.config import Settings
from proxmox_mcp.rbac import Role, role_from_mcp_name
from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.server.auth_context import get_request_session

_SESSION_TTL = timedelta(hours=1)


def build_auth_resolver(
    settings: Settings,
) -> Callable[[ToolRequest], AuthenticatedSession | None] | None:
    if settings.auth_mode == "development":
        return None

    if settings.auth_mode != "service_token":
        raise ValueError(
            f"Auth mode {settings.auth_mode!r} requires an external gateway integration"
        )

    def resolve(request: ToolRequest) -> AuthenticatedSession | None:
        _ = request
        return get_request_session()

    return resolve


def build_service_token_authenticator(settings: Settings) -> ServiceTokenAuthenticator:
    return ServiceTokenAuthenticator(
        expected_token=(
            settings.service_token.get_secret_value()
            if settings.service_token is not None
            else None
        ),
        expected_token_sha256=settings.service_token_sha256,
        session_ttl=_SESSION_TTL,
    )


def default_actor_identity(settings: Settings) -> ActorIdentity:
    return ActorIdentity(
        user_id=settings.default_actor.user_id,
        agent_id=settings.default_actor.agent_id,
        tenant_id=settings.default_actor.tenant_id,
    )


def resolve_mcp_role(role_name: str) -> Role:
    return role_from_mcp_name(role_name)


def authenticate_bearer_token(
    settings: Settings,
    token: str,
    *,
    now: datetime | None = None,
) -> AuthenticatedSession | None:
    issued_at = datetime.now(UTC) if now is None else now
    presented_hash = ServiceTokenAuthenticator.sha256_token_hash(token)

    for binding in settings.service_token_actors:
        if hmac.compare_digest(presented_hash, binding.token_sha256):
            return AuthenticatedSession(
                session_id=f"sess_bind_{binding.agent_id}",
                identity=ActorIdentity(
                    user_id=binding.user_id,
                    agent_id=binding.agent_id,
                    tenant_id=binding.tenant_id,
                ),
                auth_method="service_token",
                status="active",
                issued_at=issued_at,
                expires_at=issued_at + _SESSION_TTL,
            )

    authenticator = build_service_token_authenticator(settings)
    return authenticator.authenticate(
        token,
        identity=default_actor_identity(settings),
        now=issued_at,
    )
