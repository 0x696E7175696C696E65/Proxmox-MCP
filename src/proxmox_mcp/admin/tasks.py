"""Admin Proxmox UPID / task tracker APIs."""

from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxmox_mcp.admin.app import _state, _write_admin_audit
from proxmox_mcp.admin.auth import get_admin_session
from proxmox_mcp.security.redaction import sanitize_for_security_boundary


def _task_public(task: Any) -> dict[str, object]:
    payload = {
        "task_id": task.task_id,
        "upid": task.upid,
        "operation": task.operation,
        "method": task.method,
        "endpoint": task.endpoint,
        "target": task.target,
        "status": task.status,
        "retryable": task.retryable,
        "last_observed_state": task.last_observed_state,
        "created_at": task.created_at.isoformat(),
        "updated_at": task.updated_at.isoformat(),
        "node": (task.target or {}).get("node") if isinstance(task.target, dict) else None,
    }
    sanitized = sanitize_for_security_boundary(payload)
    return sanitized if isinstance(sanitized, dict) else payload


async def list_tasks(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role == "viewer" and request.method != "GET":
        return JSONResponse({"detail": "Viewer role is read-only"}, status_code=403)
    store = getattr(state, "proxmox_task_store", None)
    if store is None or not hasattr(store, "list_tasks"):
        return JSONResponse({"tasks": [], "count": 0})
    status = request.query_params.get("status")
    node = request.query_params.get("node")
    try:
        limit = int(request.query_params.get("limit") or "100")
    except ValueError:
        limit = 100
    tasks = await store.list_tasks(limit=limit, status=status, node=node)
    return JSONResponse({"tasks": [_task_public(t) for t in tasks], "count": len(tasks)})


async def get_task(request: Request) -> Response:
    state = _state(request)
    store = getattr(state, "proxmox_task_store", None)
    if store is None or not hasattr(store, "get_by_upid"):
        return JSONResponse({"detail": "Task store unavailable"}, status_code=503)
    upid = request.path_params["upid"]
    try:
        task = await store.get_by_upid(upid)
    except KeyError:
        return JSONResponse({"detail": "Task not found"}, status_code=404)
    return JSONResponse({"task": _task_public(task)})


async def refresh_task(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role == "viewer":
        return JSONResponse({"detail": "Viewer role is read-only"}, status_code=403)
    store = getattr(state, "proxmox_task_store", None)
    if store is None or not hasattr(store, "get_by_upid"):
        return JSONResponse({"detail": "Task store unavailable"}, status_code=503)
    upid = request.path_params["upid"]
    try:
        task = await store.get_by_upid(upid)
    except KeyError:
        return JSONResponse({"detail": "Task not found"}, status_code=404)

    client = getattr(state, "proxmox_client", None)
    observed_status = task.status
    last_state = task.last_observed_state
    if client is not None:
        node = None
        if isinstance(task.target, dict):
            node = task.target.get("node")
        if not isinstance(node, str) or not node:
            parts = upid.split(":")
            node = parts[1] if len(parts) >= 2 and parts[0] == "UPID" else None
        if isinstance(node, str) and node:
            try:
                data = await client.get(f"/nodes/{node}/tasks/{upid}/status")
                if isinstance(data, dict):
                    observed_status = str(data.get("status") or observed_status)
                    last_state = str(data.get("exitstatus") or data.get("status") or last_state)
            except Exception as exc:  # noqa: BLE001 - surface refresh failure
                await _write_admin_audit(
                    state,
                    session=session,
                    tool_name="admin.tasks.refresh",
                    operation="refresh",
                    result_status="error",
                    metadata={"upid": upid, "error": type(exc).__name__},
                )
                return JSONResponse(
                    {"detail": "Failed to refresh task from Proxmox", "upid": upid},
                    status_code=502,
                )

    if hasattr(store, "update_observed_state"):
        task = await store.update_observed_state(
            upid,
            status=observed_status,
            last_observed_state=last_state,
        )
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.tasks.refresh",
        operation="refresh",
        result_status="success",
        metadata={"upid": upid, "status": observed_status},
    )
    return JSONResponse({"task": _task_public(task)})
