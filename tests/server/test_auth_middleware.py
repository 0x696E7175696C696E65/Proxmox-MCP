# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import pytest
from pydantic import SecretStr
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from proxmox_mcp.config import Settings
from proxmox_mcp.security.rate_limit import SlidingWindowRateLimiter
from proxmox_mcp.server.auth_context import get_request_session
from proxmox_mcp.server.auth_middleware import ServiceTokenAuthMiddleware


async def _health(_: Request) -> PlainTextResponse:
    session = get_request_session()
    status = "authenticated" if session is not None else "anonymous"
    return PlainTextResponse(status)


def _build_app(settings: Settings) -> Starlette:
    app = Starlette(routes=[Route("/mcp", _health)])
    app.add_middleware(ServiceTokenAuthMiddleware, settings=settings)
    return app


def test_service_token_middleware_accepts_valid_bearer_token() -> None:
    settings = Settings(
        auth_mode="service_token",
        service_token=SecretStr("expected-token"),
    )
    client = TestClient(_build_app(settings))

    response = client.get("/mcp", headers={"Authorization": "Bearer expected-token"})

    assert response.status_code == 200
    assert response.text == "authenticated"


def test_service_token_middleware_rejects_missing_token() -> None:
    settings = Settings(
        auth_mode="service_token",
        service_token=SecretStr("expected-token"),
    )
    client = TestClient(_build_app(settings))

    response = client.get("/mcp")

    assert response.status_code == 401


def test_service_token_middleware_allows_health_paths_without_auth() -> None:
    settings = Settings(
        auth_mode="service_token",
        service_token=SecretStr("expected-token"),
    )
    app = Starlette(routes=[Route("/health/live", _health)])
    app.add_middleware(ServiceTokenAuthMiddleware, settings=settings)
    client = TestClient(app)

    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.text == "anonymous"


def test_service_token_middleware_rate_limits_failed_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limiter = SlidingWindowRateLimiter(max_failures=3, window_seconds=60.0)
    monkeypatch.setattr(
        "proxmox_mcp.server.auth_middleware.FAILED_AUTH_LIMITER",
        limiter,
    )
    settings = Settings(
        auth_mode="service_token",
        service_token=SecretStr("expected-token"),
    )
    client = TestClient(_build_app(settings))

    for _ in range(3):
        assert client.get("/mcp", headers={"Authorization": "Bearer wrong"}).status_code == 401

    limited = client.get("/mcp", headers={"Authorization": "Bearer wrong"})
    assert limited.status_code == 429
    assert limited.headers.get("retry-after") == "60"
