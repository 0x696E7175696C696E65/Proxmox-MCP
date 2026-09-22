from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from pydantic import BaseModel, Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from proxmox_mcp.admin.auth import (
    CSRF_HEADER,
    SESSION_COOKIE,
    AdminIdentityProvider,
    AdminSession,
    get_admin_session,
    reset_admin_session,
    set_admin_session,
)
from proxmox_mcp.admin.auth.providers import SESSION_IDLE_TTL
from proxmox_mcp.admin.config_store import (
    AdminConfigUpdate,
    AdminSecretsUpdate,
    ConfigStore,
    RuntimeController,
)
from proxmox_mcp.admin.events import AdminEventHub, format_sse
from proxmox_mcp.admin.hosts_store import HostCatalogStore
from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.audit.repository import AuditEventRepository
from proxmox_mcp.audit.writer import AuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.security.rate_limit import (
    FAILED_ADMIN_LOGIN_LIMITER,
    FAILED_ADMIN_STEP_UP_LIMITER,
    SlidingWindowRateLimiter,
)

SECRETS_REVEAL_LIMITER = SlidingWindowRateLimiter(max_failures=5, window_seconds=60.0)

_ADMIN_ONLY_PATHS = {
    ("PUT", "/admin/api/secrets"),
    ("POST", "/admin/api/secrets/reveal"),
    ("POST", "/admin/api/runtime/restart"),
    ("PUT", "/admin/api/policy"),
    ("PUT", "/admin/api/config"),
}


def _is_admin_only_path(method: str, path: str) -> bool:
    if (method, path) in _ADMIN_ONLY_PATHS:
        return True
    return (
        method == "POST" and path.startswith("/admin/api/approvals/") and path.endswith("/decide")
    )


def _cookie_secure(settings: Settings, request: Request) -> bool:
    return settings.environment == "production" or request.url.scheme == "https"


def _set_session_cookie(
    response: Response,
    *,
    session_id: str,
    settings: Settings,
    request: Request,
) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        secure=_cookie_secure(settings, request),
        samesite="lax",
        max_age=int(SESSION_IDLE_TTL.total_seconds()),
        path="/",
    )


def _clear_session_cookie(
    response: Response,
    *,
    settings: Settings,
    request: Request,
) -> None:
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=_cookie_secure(settings, request),
        httponly=True,
        samesite="lax",
    )


async def _audit_auth_event(
    state: AdminAppState,
    *,
    tool_name: str,
    operation: str,
    result_status: str,
    actor_user_id: str,
    metadata: dict[str, object] | None = None,
) -> None:
    event = AuditEvent(
        event_type="admin.action",
        correlation_id=f"admin_{uuid4().hex}",
        actor_user_id=actor_user_id,
        actor_agent_id="admin-ui",
        tool_name=tool_name,
        operation=operation,
        target=AuditTarget(resource_type="admin", resource_id=tool_name),
        result_status=result_status,  # type: ignore[arg-type]
        metadata=metadata or {},
    )
    await state.audit_writer.write(event)


def _require_admin_role(session: AdminSession) -> JSONResponse | None:
    if session.identity.role != "admin":
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    return None


def _step_up_rate_key(request: Request, session: AdminSession) -> str:
    ip = request.client.host if request.client is not None else "unknown"
    return f"{session.session_id}:{ip}"


def _build_liveness_payload(settings: Settings) -> dict[str, object]:
    from proxmox_mcp.server.health import build_liveness_payload

    return build_liveness_payload(settings).model_dump(mode="json")


async def _build_readiness_payload(
    settings: Settings,
    dependency_checkers: dict[str, Any] | None,
) -> dict[str, object]:
    from proxmox_mcp.server.health import DependencyChecker, build_readiness_payload

    checkers: dict[str, DependencyChecker] | None = None
    if dependency_checkers is not None:
        checkers = cast(dict[str, DependencyChecker], dependency_checkers)
    payload = await build_readiness_payload(settings, checkers)
    return payload.model_dump(mode="json")


class LoginBody(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class RevealBody(BaseModel):
    name: str
    password: str = Field(min_length=1)


class SecretsUpdateBody(AdminSecretsUpdate):
    password: str = Field(min_length=1)


class RestartBody(BaseModel):
    password: str = Field(min_length=1)
    config_version: str | None = None


class ConfigUpdateBody(AdminConfigUpdate):
    config_version: str | None = None


@dataclass(slots=True)
class AdminAppState:
    settings: Settings
    identity_provider: AdminIdentityProvider
    config_store: ConfigStore
    runtime: RuntimeController
    audit_repository: AuditEventRepository
    audit_writer: AuditWriter
    event_hub: AdminEventHub
    dependency_checkers: dict[str, Any] | None
    spa_dir: Path | None
    tool_registry: Any | None = None
    tool_context_factory: Any | None = None
    approval_store: Any | None = None
    host_catalog: HostCatalogStore | None = None


async def verify_admin_step_up(
    request: Request,
    *,
    state: AdminAppState,
    session: AdminSession,
    password: str,
    operation: str,
    metadata: dict[str, object] | None = None,
) -> JSONResponse | None:
    """Verify re-entered admin password with shared rate limiting.

    Returns an error Response on failure, or None when step-up succeeds.
    """
    key = _step_up_rate_key(request, session)
    if FAILED_ADMIN_STEP_UP_LIMITER.is_limited(key):
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation=operation,
            result_status="denied",
            metadata={
                **(metadata or {}),
                "reason": "step_up_rate_limited",
                "client_ip": key.split(":", 1)[-1],
            },
        )
        return JSONResponse(
            {"detail": "Too many step-up authentication failures"},
            status_code=429,
            headers={"Retry-After": "60"},
        )
    if not await state.identity_provider.verify_user_password(session.identity.user_id, password):
        FAILED_ADMIN_STEP_UP_LIMITER.record_failure(key)
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation=operation,
            result_status="denied",
            metadata={**(metadata or {}), "reason": "step_up_failed"},
        )
        await asyncio.sleep(0.2)
        return JSONResponse({"detail": "Step-up authentication failed"}, status_code=403)
    FAILED_ADMIN_STEP_UP_LIMITER.reset(key)
    return None


_PUBLIC_API_PATHS = {
    "/admin/api/auth/login",
    "/admin/api/health/live",
}


class AdminSessionMiddleware:
    """Pure ASGI middleware — avoids BaseHTTPMiddleware/asyncpg loop conflicts."""

    def __init__(self, app: ASGIApp, *, provider: AdminIdentityProvider) -> None:
        self.app = app
        self._provider = provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        path = request.url.path
        if not path.startswith("/admin/api"):
            await self.app(scope, receive, send)
            return

        session_id = request.cookies.get(SESSION_COOKIE)
        session = await self._provider.get_session(session_id) if session_id else None
        token = set_admin_session(session)
        request.state.admin_session = session
        try:
            if path in _PUBLIC_API_PATHS:
                await self.app(scope, receive, send)
                return

            if session is None:
                response = JSONResponse({"detail": "Authentication required"}, status_code=401)
                await response(scope, receive, send)
                return

            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                import hmac

                csrf = request.headers.get(CSRF_HEADER)
                if csrf is None or not hmac.compare_digest(csrf, session.csrf_token):
                    response = JSONResponse({"detail": "CSRF token invalid"}, status_code=403)
                    await response(scope, receive, send)
                    return
                origin = request.headers.get("origin")
                if origin is not None:
                    host = request.headers.get("host", request.url.netloc)
                    allowed = {
                        f"{request.url.scheme}://{host}",
                        f"https://{host}",
                    }
                    if request.url.scheme == "http":
                        allowed.add(f"http://{host}")
                    if origin.rstrip("/") not in {item.rstrip("/") for item in allowed}:
                        response = JSONResponse({"detail": "Origin not allowed"}, status_code=403)
                        await response(scope, receive, send)
                        return

            if _is_admin_only_path(request.method, path) and session.identity.role != "admin":
                response = JSONResponse({"detail": "Admin role required"}, status_code=403)
                await response(scope, receive, send)
                return

            await self.app(scope, receive, send)
        finally:
            reset_admin_session(token)


def _state(request: Request) -> AdminAppState:
    return request.app.state.admin  # type: ignore[no-any-return]


async def _write_admin_audit(
    state: AdminAppState,
    *,
    session: AdminSession,
    tool_name: str,
    operation: str,
    result_status: str,
    metadata: dict[str, object] | None = None,
) -> None:
    event = AuditEvent(
        event_type="admin.action",
        correlation_id=f"admin_{uuid4().hex}",
        actor_user_id=session.identity.username,
        actor_agent_id="admin-ui",
        tool_name=tool_name,
        operation=operation,
        target=AuditTarget(resource_type="admin", resource_id=tool_name),
        result_status=result_status,  # type: ignore[arg-type]
        metadata=metadata or {},
    )
    await state.audit_writer.write(event)


async def login(request: Request) -> Response:
    state = _state(request)
    client_key = request.client.host if request.client is not None else "unknown"
    if FAILED_ADMIN_LOGIN_LIMITER.is_limited(client_key):
        await _audit_auth_event(
            state,
            tool_name="admin.login",
            operation="login",
            result_status="denied",
            actor_user_id="anonymous",
            metadata={"client_ip": client_key, "reason": "rate_limited"},
        )
        return JSONResponse(
            {"detail": "Too many failed login attempts"},
            status_code=429,
            headers={"Retry-After": "60"},
        )
    body = LoginBody.model_validate(await request.json())
    identity = await state.identity_provider.authenticate(body.username, body.password)
    if identity is None:
        FAILED_ADMIN_LOGIN_LIMITER.record_failure(client_key)
        await _audit_auth_event(
            state,
            tool_name="admin.login",
            operation="login",
            result_status="denied",
            actor_user_id=body.username,
            metadata={"client_ip": client_key, "reason": "invalid_credentials"},
        )
        await asyncio.sleep(0.2)
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
    FAILED_ADMIN_LOGIN_LIMITER.reset(client_key)
    session = await state.identity_provider.create_session(identity)
    await _audit_auth_event(
        state,
        tool_name="admin.login",
        operation="login",
        result_status="success",
        actor_user_id=identity.username,
        metadata={"client_ip": client_key, "role": identity.role},
    )
    response = JSONResponse(
        {
            "user": {
                "user_id": identity.user_id,
                "username": identity.username,
                "role": identity.role,
            },
            "csrf_token": session.csrf_token,
            "expires_at": session.expires_at.isoformat(),
        }
    )
    _set_session_cookie(
        response,
        session_id=session.session_id,
        settings=state.settings,
        request=request,
    )
    return response


async def logout(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    if session is not None:
        await state.identity_provider.revoke_session(session.session_id)
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.logout",
            operation="logout",
            result_status="success",
        )
    response = JSONResponse({"ok": True})
    _clear_session_cookie(response, settings=state.settings, request=request)
    return response


async def me(request: Request) -> Response:
    session = get_admin_session()
    assert session is not None
    return JSONResponse(
        {
            "user": {
                "user_id": session.identity.user_id,
                "username": session.identity.username,
                "role": session.identity.role,
            },
            "csrf_token": session.csrf_token,
            "expires_at": session.expires_at.isoformat(),
        }
    )


async def health_live(request: Request) -> Response:
    state = _state(request)
    return JSONResponse({"live": _build_liveness_payload(state.settings)})


async def health(request: Request) -> Response:
    state = _state(request)
    live = _build_liveness_payload(state.settings)
    ready = await _build_readiness_payload(state.settings, state.dependency_checkers)
    status_code = 200 if ready.get("status") == "ready" else 503
    return JSONResponse({"live": live, "ready": ready}, status_code=status_code)


async def overview(request: Request) -> Response:
    state = _state(request)
    events = await state.audit_repository.list_events(limit=10)
    failures = [e for e in events if e.get("result_status") in {"error", "denied"}]
    return JSONResponse(
        {
            "config": state.config_store.public_config(),
            "runtime": state.runtime.status,
            "recent_events": events[:5],
            "recent_failures": failures[:5],
            "health": _build_liveness_payload(state.settings),
        }
    )


async def list_audit(request: Request) -> Response:
    state = _state(request)
    params = request.query_params
    limit = int(params.get("limit", "50"))
    tool_name = params.get("tool_name")
    result_status = params.get("result_status")
    actor_user_id = params.get("actor_user_id")
    cursor = params.get("cursor")
    events = await state.audit_repository.list_events(
        limit=limit,
        tool_name=tool_name,
        result_status=result_status,
        actor_user_id=actor_user_id,
        cursor=cursor,
    )
    next_cursor = events[-1]["event_id"] if events else None
    return JSONResponse({"events": events, "next_cursor": next_cursor})


async def get_audit(request: Request) -> Response:
    state = _state(request)
    event_id = request.path_params["event_id"]
    event = await state.audit_repository.get_event(event_id)
    if event is None:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return JSONResponse({"event": event})


async def stream_events(request: Request) -> Response:
    state = _state(request)

    async def event_generator() -> AsyncIterator[bytes]:
        yield format_sse({"type": "runtime.status", "payload": state.runtime.status})
        async for event in state.event_hub.subscribe():
            if await request.is_disconnected():
                break
            yield format_sse(event)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


async def get_config(request: Request) -> Response:
    return JSONResponse(_state(request).config_store.public_config())


async def put_config(request: Request) -> Response:
    import hashlib
    import json

    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="update_config",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    update = ConfigUpdateBody.model_validate(await request.json())
    if (
        update.dangerous_operations_enabled is not None
        or update.dangerous_operations_require_approval is not None
    ):
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="update_config",
            result_status="denied",
            metadata={"reason": "policy_via_config_forbidden"},
        )
        return JSONResponse(
            {
                "detail": (
                    "Dangerous-operations policy must be changed via "
                    "PUT /admin/api/policy with step-up authentication"
                )
            },
            status_code=403,
        )
    expected = update.config_version or request.headers.get("if-match")
    current_version = state.config_store.config_version()
    if expected is not None and expected.strip('"') != current_version:
        return JSONResponse(
            {"detail": "Config version mismatch", "config_version": current_version},
            status_code=409,
        )
    result = state.config_store.apply_config(update)
    content_hash = hashlib.sha256(
        json.dumps(
            update.model_dump(exclude_none=True, exclude={"config_version"}),
            sort_keys=True,
            default=str,
        ).encode()
    ).hexdigest()
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.config.update",
        operation="update_config",
        result_status="success",
        metadata={
            "changed_fields": list(result.changed_fields),
            "kind": result.kind,
            "content_hash": content_hash,
            "config_version": state.config_store.config_version(),
        },
    )
    await state.event_hub.publish(
        "runtime.applied", {"result": result.message, "kind": result.kind}
    )
    return JSONResponse(
        {
            "result": {
                "kind": result.kind,
                "changed_fields": list(result.changed_fields),
                "message": result.message,
            },
            "config": state.config_store.public_config(),
            "runtime": state.runtime.status,
        }
    )


async def get_secrets(request: Request) -> Response:
    return JSONResponse(_state(request).config_store.public_secrets())


async def put_secrets(request: Request) -> Response:
    import hashlib
    import json

    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="update_secrets",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    update = SecretsUpdateBody.model_validate(await request.json())
    step_up_denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=update.password,
        operation="update_secrets",
    )
    if step_up_denied is not None:
        return step_up_denied
    expected = update.config_version or request.headers.get("if-match")
    current_version = state.config_store.secrets_version()
    if expected is not None and expected.strip('"') != current_version:
        return JSONResponse(
            {"detail": "Secrets version mismatch", "config_version": current_version},
            status_code=409,
        )
    result = state.config_store.apply_secrets(update)
    content_hash = hashlib.sha256(
        json.dumps(list(result.changed_fields), sort_keys=True).encode()
    ).hexdigest()
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.secrets.update",
        operation="update_secrets",
        result_status="success",
        metadata={
            "changed_fields": list(result.changed_fields),
            "kind": result.kind,
            "content_hash": content_hash,
        },
    )
    await state.event_hub.publish(
        "runtime.restart_required" if result.kind == "restart" else "runtime.applied",
        {"result": result.message, "kind": result.kind},
    )
    return JSONResponse(
        {
            "result": {
                "kind": result.kind,
                "changed_fields": list(result.changed_fields),
                "message": result.message,
            },
            "secrets": state.config_store.public_secrets(),
            "runtime": state.runtime.status,
        }
    )


async def reveal_secret(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="reveal_secret",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    client_key = request.client.host if request.client is not None else "unknown"
    if SECRETS_REVEAL_LIMITER.is_limited(client_key):
        return JSONResponse(
            {"detail": "Too many secret reveal attempts"},
            status_code=429,
            headers={"Retry-After": "60"},
        )
    body = RevealBody.model_validate(await request.json())
    if body.name not in {"proxmox_token_secret", "service_token"}:
        return JSONResponse({"detail": "Unknown secret"}, status_code=422)
    step_up_denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="reveal_secret",
        metadata={"name": body.name},
    )
    if step_up_denied is not None:
        if step_up_denied.status_code == 403:
            SECRETS_REVEAL_LIMITER.record_failure(client_key)
        return step_up_denied
    SECRETS_REVEAL_LIMITER.reset(client_key)
    value = state.config_store.reveal_secret(body.name)  # type: ignore[arg-type]
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.secrets.reveal",
        operation="reveal_secret",
        result_status="success",
        metadata={"name": body.name},
    )
    return JSONResponse({"name": body.name, "value": value})


async def get_runtime(request: Request) -> Response:
    return JSONResponse(_state(request).runtime.status)


async def post_restart(request: Request) -> Response:
    from pydantic import ValidationError

    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="restart",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    try:
        body = RestartBody.model_validate(await request.json())
    except ValidationError as exc:
        return JSONResponse({"detail": exc.errors()}, status_code=422)
    step_up_denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="restart",
    )
    if step_up_denied is not None:
        return step_up_denied
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.runtime.restart",
        operation="restart",
        result_status="success",
    )
    await state.event_hub.publish("runtime.restart_requested", {})
    response = JSONResponse({"ok": True, "message": "Restarting"})
    state.runtime.request_restart()
    return response


async def spa_index(request: Request) -> Response:
    state = _state(request)
    if state.spa_dir is None:
        return JSONResponse(
            {
                "service": "proxmox-mcp-admin",
                "message": "Admin SPA not built. API is available under /admin/api.",
            }
        )
    index = state.spa_dir / "index.html"
    if not index.is_file():
        return JSONResponse({"detail": "Admin UI missing"}, status_code=404)
    return FileResponse(index)


def create_admin_starlette_app(state: AdminAppState) -> Starlette:
    from proxmox_mcp.admin import control as admin_control
    from proxmox_mcp.admin import hosts as admin_hosts

    api_routes = [
        Route("/admin/api/auth/login", login, methods=["POST"]),
        Route("/admin/api/auth/logout", logout, methods=["POST"]),
        Route("/admin/api/me", me, methods=["GET"]),
        Route("/admin/api/health/live", health_live, methods=["GET"]),
        Route("/admin/api/health", health, methods=["GET"]),
        Route("/admin/api/health/deps", admin_control.health_deps, methods=["GET"]),
        Route("/admin/api/health/doctor", admin_control.health_doctor, methods=["POST"]),
        Route("/admin/api/overview", overview, methods=["GET"]),
        Route("/admin/api/audit", list_audit, methods=["GET"]),
        Route("/admin/api/audit/{event_id}", get_audit, methods=["GET"]),
        Route("/admin/api/events", stream_events, methods=["GET"]),
        Route("/admin/api/config", get_config, methods=["GET"]),
        Route("/admin/api/config", put_config, methods=["PUT"]),
        Route("/admin/api/secrets", get_secrets, methods=["GET"]),
        Route("/admin/api/secrets", put_secrets, methods=["PUT"]),
        Route("/admin/api/secrets/reveal", reveal_secret, methods=["POST"]),
        Route("/admin/api/runtime", get_runtime, methods=["GET"]),
        Route("/admin/api/runtime/restart", post_restart, methods=["POST"]),
        Route("/admin/api/tools", admin_control.list_tools, methods=["GET"]),
        Route("/admin/api/tools/{name}", admin_control.get_tool, methods=["GET"]),
        Route("/admin/api/tools/{name}/invoke", admin_control.invoke_tool, methods=["POST"]),
        Route("/admin/api/approvals", admin_control.list_approvals, methods=["GET"]),
        Route(
            "/admin/api/approvals/{approval_id}/decide",
            admin_control.decide_approval,
            methods=["POST"],
        ),
        Route("/admin/api/policy", admin_control.get_policy, methods=["GET"]),
        Route("/admin/api/policy", admin_control.put_policy, methods=["PUT"]),
        Route("/admin/api/hosts", admin_hosts.list_hosts, methods=["GET"]),
        Route("/admin/api/hosts", admin_hosts.create_host, methods=["POST"]),
        Route("/admin/api/hosts/{host_id}", admin_hosts.update_host, methods=["PUT"]),
        Route("/admin/api/hosts/{host_id}", admin_hosts.delete_host, methods=["DELETE"]),
        Route(
            "/admin/api/hosts/{host_id}/activate",
            admin_hosts.activate_host,
            methods=["POST"],
        ),
        Route(
            "/admin/api/hosts/{host_id}/probe",
            admin_hosts.probe_host,
            methods=["POST"],
        ),
    ]

    routes: list[Any] = list(api_routes)
    if state.spa_dir is not None and state.spa_dir.is_dir():
        assets = state.spa_dir / "assets"
        if assets.is_dir():
            routes.append(
                Mount("/admin/assets", StaticFiles(directory=assets), name="admin-assets")
            )
        routes.append(Route("/admin", spa_index, methods=["GET"]))
        routes.append(Route("/admin/{path:path}", spa_index, methods=["GET"]))
    else:
        routes.append(Route("/admin", spa_index, methods=["GET"]))
        routes.append(Route("/admin/{path:path}", spa_index, methods=["GET"]))

    app = Starlette(routes=routes)
    app.state.admin = state
    app.add_middleware(AdminSessionMiddleware, provider=state.identity_provider)
    return app


class AdminPathMiddleware:
    """ASGI middleware that routes /admin* to the admin Starlette app."""

    def __init__(self, app: Any, admin_app: Starlette) -> None:
        self.app = app
        self.admin_app = admin_app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] in {"http", "websocket"}:
            path = scope.get("path", "")
            if path == "/admin" or path.startswith("/admin/"):
                await self.admin_app(scope, receive, send)
                return
        await self.app(scope, receive, send)
