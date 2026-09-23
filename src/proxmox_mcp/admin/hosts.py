"""Admin HTTP API for the multi-host Proxmox catalog."""

from __future__ import annotations

import json
import time
from typing import Any

from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxmox_mcp.admin.app import (
    AdminAppState,
    _require_admin_role,
    _state,
    _write_admin_audit,
    verify_admin_step_up,
)
from proxmox_mcp.admin.auth import get_admin_session
from proxmox_mcp.admin.hosts_store import HostCatalogError, HostRecord

_PROBE_TIMEOUT_SECONDS = 3.0


class HostStepUpBody(BaseModel):
    password: str = Field(min_length=1)


def _host_record_from_payload(payload: dict[str, Any]) -> HostRecord:
    data = {k: v for k, v in payload.items() if k != "password"}
    return HostRecord.model_validate(data)


async def _parse_step_up_payload(
    request: Request,
    *,
    state: AdminAppState,
    session: object,
    operation: str,
    metadata: dict[str, object] | None = None,
) -> tuple[dict[str, Any] | None, Response | None]:
    try:
        raw = await request.body()
    except Exception:  # noqa: BLE001 - treat unreadable body as invalid
        return None, JSONResponse({"detail": "Invalid body"}, status_code=400)
    if not raw.strip():
        return None, JSONResponse(
            {"detail": "password is required for host catalog mutations"},
            status_code=400,
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None, JSONResponse({"detail": "Invalid JSON body"}, status_code=400)
    if not isinstance(payload, dict):
        return None, JSONResponse({"detail": "Invalid body"}, status_code=400)
    password = payload.get("password")
    if not isinstance(password, str) or not password:
        return None, JSONResponse(
            {"detail": "password is required for host catalog mutations"},
            status_code=400,
        )
    denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,  # type: ignore[arg-type]
        password=password,
        operation=operation,
        metadata=metadata,
    )
    if denied is not None:
        return None, denied
    return payload, None


def _serialize_host(
    state: AdminAppState,
    record: HostRecord,
    *,
    health: dict[str, Any] | None = None,
) -> dict[str, Any]:
    store = state.host_catalog
    assert store is not None
    payload: dict[str, Any] = {
        **record.model_dump(),
        "secrets_ready": store.secrets_ready(record.host_id),
    }
    if health is not None:
        payload["health"] = health
    return payload


def probe_host_health(state: AdminAppState, record: HostRecord) -> dict[str, Any]:
    from proxmox_mcp.security.egress import https_request_no_redirect, validate_https_url_host

    store = state.host_catalog
    assert store is not None
    entry = store.credential_entry(record.credential_ref_path)
    token_id = entry.get("token_id")
    token_secret = entry.get("token_secret")
    if not isinstance(token_id, str) or not token_id:
        return {"ok": False, "error": "token_id not configured"}
    if not isinstance(token_secret, str) or not token_secret:
        return {"ok": False, "error": "token_secret not configured"}

    # Production never sends PVE credentials over unverified TLS.
    if state.settings.environment == "production" and not record.tls_verify:
        return {
            "ok": False,
            "error": "tls_verify required for credentialed host probe in production",
        }

    base = record.api_endpoint.rstrip("/")
    if not base.startswith("https://"):
        return {"ok": False, "error": "endpoint must use https"}
    url = f"{base}/api2/json/version"
    allow_public = bool(getattr(state.settings, "host_allow_public_endpoints", False))
    try:
        validate_https_url_host(
            url,
            allow_private=True,
            allow_public=allow_public,
            resolve=True,
        )
    except ValueError as exc:
        return {"ok": False, "error": f"endpoint_policy:{exc}"}

    started = time.perf_counter()
    try:
        status, body = https_request_no_redirect(
            url,
            method="GET",
            headers={"Authorization": f"PVEAPIToken={token_id}={token_secret}"},
            timeout_seconds=_PROBE_TIMEOUT_SECONDS,
            ssl_context=_ssl_context(record),
            allow_private=True,
            allow_public=allow_public,
        )
    except ValueError as exc:
        return {
            "ok": False,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": f"endpoint_policy:{exc}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": str(exc),
        }

    latency_ms = int((time.perf_counter() - started) * 1000)
    if status >= 400:
        return {"ok": False, "latency_ms": latency_ms, "error": f"HTTP {status}"}

    version: str | None = None
    try:
        parsed = json.loads(body.decode("utf-8"))
        if isinstance(parsed, dict):
            data = parsed.get("data")
            if isinstance(data, dict):
                raw_version = data.get("version")
                if isinstance(raw_version, str):
                    version = raw_version
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    result: dict[str, Any] = {"ok": True, "latency_ms": latency_ms}
    if version is not None:
        result["version"] = version
    return result


def _ssl_context(record: HostRecord) -> Any | None:
    if record.tls_verify:
        return None
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def list_hosts(request: Request) -> Response:
    state = _state(request)
    if state.host_catalog is None:
        return JSONResponse({"detail": "Host catalog unavailable"}, status_code=503)
    catalog = state.host_catalog.seed_from_settings_if_empty()
    hosts = [_serialize_host(state, record) for record in catalog.hosts]
    return JSONResponse({"hosts": hosts, "active_host_id": catalog.active_host_id})


async def create_host(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="create_host",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    if state.host_catalog is None:
        return JSONResponse({"detail": "Host catalog unavailable"}, status_code=503)

    payload, step_denied = await _parse_step_up_payload(
        request, state=state, session=session, operation="create_host"
    )
    if step_denied is not None:
        return step_denied
    assert payload is not None
    record = _host_record_from_payload(payload)
    if state.settings.environment == "production" and not record.tls_verify:
        return JSONResponse(
            {"detail": "tls_verify must be true for hosts in production"},
            status_code=400,
        )
    catalog = state.host_catalog.load()
    if any(h.host_id == record.host_id for h in catalog.hosts):
        await _write_admin_audit(
            state,
            session=session,
            tool_name="hosts.create",
            operation="create",
            result_status="error",
            metadata={"host_id": record.host_id, "error": "already exists"},
        )
        return JSONResponse({"detail": "Host already exists"}, status_code=409)

    state.host_catalog.upsert(record)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="hosts.create",
        operation="create",
        result_status="success",
        metadata={"host_id": record.host_id},
    )
    return JSONResponse({"host": _serialize_host(state, record)}, status_code=201)


async def update_host(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="update_host",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    if state.host_catalog is None:
        return JSONResponse({"detail": "Host catalog unavailable"}, status_code=503)

    host_id = request.path_params["host_id"]
    payload, step_denied = await _parse_step_up_payload(
        request,
        state=state,
        session=session,
        operation="update_host",
        metadata={"host_id": host_id},
    )
    if step_denied is not None:
        return step_denied
    assert payload is not None
    body = _host_record_from_payload(payload)
    if body.host_id != host_id:
        return JSONResponse({"detail": "host_id in body must match path"}, status_code=422)
    if state.settings.environment == "production" and not body.tls_verify:
        return JSONResponse(
            {"detail": "tls_verify must be true for hosts in production"},
            status_code=400,
        )

    catalog = state.host_catalog.load()
    if not any(h.host_id == host_id for h in catalog.hosts):
        return JSONResponse({"detail": "Host not found"}, status_code=404)

    state.host_catalog.upsert(body)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="hosts.update",
        operation="update",
        result_status="success",
        metadata={"host_id": host_id},
    )
    return JSONResponse({"host": _serialize_host(state, body)})


async def delete_host(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="delete_host",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    if state.host_catalog is None:
        return JSONResponse({"detail": "Host catalog unavailable"}, status_code=503)

    host_id = request.path_params["host_id"]
    payload, step_denied = await _parse_step_up_payload(
        request,
        state=state,
        session=session,
        operation="delete_host",
        metadata={"host_id": host_id},
    )
    if step_denied is not None:
        return step_denied
    _ = payload
    try:
        state.host_catalog.delete(host_id)
    except HostCatalogError as exc:
        status = 404 if "not found" in str(exc).lower() else 409
        await _write_admin_audit(
            state,
            session=session,
            tool_name="hosts.delete",
            operation="delete",
            result_status="error",
            metadata={"host_id": host_id, "error": str(exc)},
        )
        return JSONResponse({"detail": str(exc)}, status_code=status)

    await _write_admin_audit(
        state,
        session=session,
        tool_name="hosts.delete",
        operation="delete",
        result_status="success",
        metadata={"host_id": host_id},
    )
    return JSONResponse({"ok": True, "host_id": host_id})


async def activate_host(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="activate_host",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    if state.host_catalog is None:
        return JSONResponse({"detail": "Host catalog unavailable"}, status_code=503)

    host_id = request.path_params["host_id"]
    payload, step_denied = await _parse_step_up_payload(
        request,
        state=state,
        session=session,
        operation="activate_host",
        metadata={"host_id": host_id},
    )
    if step_denied is not None:
        return step_denied
    _ = payload
    try:
        plan = state.host_catalog.activate(host_id)
    except HostCatalogError as exc:
        message = str(exc)
        status = 404 if "not found" in message.lower() else 400
        await _write_admin_audit(
            state,
            session=session,
            tool_name="hosts.activate",
            operation="activate",
            result_status="error",
            metadata={"host_id": host_id, "error": message},
        )
        return JSONResponse({"detail": message}, status_code=status)

    await _write_admin_audit(
        state,
        session=session,
        tool_name="hosts.activate",
        operation="activate",
        result_status="success",
        metadata={"host_id": plan.host_id},
    )
    await state.event_hub.publish("runtime.restart_requested", {"host_id": plan.host_id})
    response = JSONResponse(
        {
            "ok": True,
            "host_id": plan.host_id,
            "restarting": True,
            "message": "Switching managed host; MCP is restarting",
        }
    )
    state.runtime.request_restart()
    return response


async def probe_host(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin_role(session)
    if denied is not None:
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="probe_host",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return denied
    if state.host_catalog is None:
        return JSONResponse({"detail": "Host catalog unavailable"}, status_code=503)

    host_id = request.path_params["host_id"]
    payload, step_denied = await _parse_step_up_payload(
        request,
        state=state,
        session=session,
        operation="probe_host",
        metadata={"host_id": host_id},
    )
    if step_denied is not None:
        return step_denied
    _ = payload
    catalog = state.host_catalog.load()
    record = next((h for h in catalog.hosts if h.host_id == host_id), None)
    if record is None:
        return JSONResponse({"detail": "Host not found"}, status_code=404)

    health = probe_host_health(state, record)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="hosts.probe",
        operation="probe",
        result_status="success" if health.get("ok") else "error",
        metadata={"host_id": host_id, "ok": bool(health.get("ok"))},
    )
    return JSONResponse({"host_id": host_id, "health": health})
