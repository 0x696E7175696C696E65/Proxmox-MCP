from __future__ import annotations

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from proxmox_mcp.config import Settings
from proxmox_mcp.server.auth_context import reset_request_session, set_request_session
from proxmox_mcp.server.auth_resolver import authenticate_bearer_token

_PUBLIC_PATH_PREFIXES = ("/health/", "/metrics")


class ServiceTokenAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        if _is_public_path(request.url.path):
            return await call_next(request)

        if self._settings.auth_mode != "service_token":
            return await call_next(request)

        authorization = request.headers.get("authorization", "")
        if not authorization.lower().startswith("bearer "):
            return JSONResponse({"detail": "Authorization bearer token required"}, status_code=401)

        token = authorization[7:].strip()
        if not token:
            return JSONResponse({"detail": "Authorization bearer token required"}, status_code=401)

        session = authenticate_bearer_token(self._settings, token)
        if session is None:
            return JSONResponse({"detail": "Invalid bearer token"}, status_code=401)

        token_handle = set_request_session(session)
        try:
            return await call_next(request)
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
