from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from proxmox_mcp.config import Settings
from proxmox_mcp.security.rate_limit import FAILED_AUTH_LIMITER, client_ip_from_scope
from proxmox_mcp.server.auth_context import reset_request_session, set_request_session
from proxmox_mcp.server.auth_resolver import authenticate_bearer_token

# /admin is excluded from service-token auth: AdminPathMiddleware + cookie sessions
# own that surface. /health/* stays anonymous; /metrics requires bearer.
_PUBLIC_PATH_PREFIXES = ("/health/", "/admin")


class ServiceTokenAuthMiddleware:
    """Pure ASGI middleware — avoids BaseHTTPMiddleware/asyncpg loop conflicts."""

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        self.app = app
        self._settings = settings
        self._rate_limiter = FAILED_AUTH_LIMITER

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        if _is_public_path(request.url.path) or self._settings.auth_mode != "service_token":
            await self.app(scope, receive, send)
            return

        client_key = client_ip_from_scope(dict(scope))
        if self._rate_limiter.is_limited(client_key):
            response = JSONResponse(
                {"detail": "Too many failed authentication attempts"},
                status_code=429,
                headers={"Retry-After": "60"},
            )
            await response(scope, receive, send)
            return

        authorization = request.headers.get("authorization", "")
        if not authorization.lower().startswith("bearer "):
            self._rate_limiter.record_failure(client_key)
            response = JSONResponse(
                {"detail": "Authorization bearer token required"}, status_code=401
            )
            await response(scope, receive, send)
            return

        token = authorization[7:].strip()
        if not token:
            self._rate_limiter.record_failure(client_key)
            response = JSONResponse(
                {"detail": "Authorization bearer token required"}, status_code=401
            )
            await response(scope, receive, send)
            return

        session = authenticate_bearer_token(self._settings, token)
        if session is None:
            self._rate_limiter.record_failure(client_key)
            from proxmox_mcp.observability import structured_log

            structured_log(
                event="auth.failed",
                client_ip=client_key,
                path=request.url.path,
                reason="invalid_token",
            )
            response = JSONResponse({"detail": "Invalid bearer token"}, status_code=401)
            await response(scope, receive, send)
            return

        self._rate_limiter.reset(client_key)
        token_handle = set_request_session(session)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_request_session(token_handle)


def _is_public_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in _PUBLIC_PATH_PREFIXES)


def attach_service_token_middleware(app: object, *, settings: Settings) -> None:
    if settings.auth_mode != "service_token":
        return

    starlette_app = _resolve_starlette_app(app)
    if starlette_app is None:
        return

    starlette_app.add_middleware(ServiceTokenAuthMiddleware, settings=settings)


def _resolve_starlette_app(app: object) -> Starlette | None:
    for attribute in ("http_app", "_http_app", "app", "_app"):
        candidate = getattr(app, attribute, None)
        if isinstance(candidate, Starlette):
            return candidate
    return None
