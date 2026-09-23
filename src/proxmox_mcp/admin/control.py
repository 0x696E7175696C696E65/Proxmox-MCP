"""Admin control-plane APIs: tools, health deps/doctor, approvals, policy."""

from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxmox_mcp.admin.app import (
    _build_liveness_payload,
    _build_readiness_payload,
    _state,
    _write_admin_audit,
    verify_admin_step_up,
)
from proxmox_mcp.admin.auth import get_admin_session
from proxmox_mcp.admin.config_store import AdminConfigUpdate
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest


class ToolInvokeBody(BaseModel):
    target: Target
    parameters: dict[str, object] = Field(default_factory=dict)
    dry_run: bool = True
    password: str | None = Field(default=None, min_length=1)


class ApprovalDecideBody(BaseModel):
    decision: Literal["approved", "rejected"]
    reason: str | None = None
    password: str = Field(min_length=1)


class PolicyBody(BaseModel):
    dangerous_operations_enabled: bool | None = None
    dangerous_operations_require_approval: bool | None = None
    password: str = Field(min_length=1)


def _tool_summary(definition: Any) -> dict[str, object]:
    return {
        "name": definition.name,
        "description": definition.description,
        "category": definition.category,
        "permission": definition.permission,
        "risk": definition.risk,
        "dry_run": definition.dry_run,
        "approval_default": definition.approval_default,
        "connector": definition.connector,
        "invokable": definition.risk in {"low", "medium"},
    }


async def list_tools(request: Request) -> Response:
    state = _state(request)
    if state.tool_registry is None:
        return JSONResponse({"detail": "Tool registry unavailable"}, status_code=503)
    risk = request.query_params.get("risk")
    q = (request.query_params.get("q") or "").strip().lower()
    tools = [_tool_summary(d) for d in state.tool_registry.definitions()]
    if risk:
        tools = [t for t in tools if t["risk"] == risk]
    if q:
        tools = [
            t for t in tools if q in str(t["name"]).lower() or q in str(t["description"]).lower()
        ]
    tools.sort(key=lambda t: str(t["name"]))
    return JSONResponse({"tools": tools, "count": len(tools)})


async def get_tool(request: Request) -> Response:
    state = _state(request)
    if state.tool_registry is None:
        return JSONResponse({"detail": "Tool registry unavailable"}, status_code=503)
    name = request.path_params["name"]
    try:
        definition = state.tool_registry.get(name)
    except KeyError:
        return JSONResponse({"detail": "Tool not found"}, status_code=404)
    schema = next((s for s in state.tool_registry.schemas() if s.name == name), None)
    return JSONResponse(
        {
            "tool": _tool_summary(definition),
            "parameters_schema": None if schema is None else schema.parameters_schema,
            "result_schema": None if schema is None else schema.result_schema,
        }
    )


async def invoke_tool(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role != "admin":
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="invoke_tool",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    if state.tool_registry is None or state.tool_context_factory is None:
        return JSONResponse({"detail": "Tool registry unavailable"}, status_code=503)

    name = request.path_params["name"]
    try:
        definition = state.tool_registry.get(name)
    except KeyError:
        return JSONResponse({"detail": "Tool not found"}, status_code=404)

    if definition.risk in {"high", "critical"}:
        return JSONResponse(
            {
                "detail": (
                    "High/critical tools cannot be invoked from the UI; use Approvals workflow."
                ),
                "risk": definition.risk,
            },
            status_code=403,
        )

    body = ToolInvokeBody.model_validate(await request.json())
    if definition.risk == "medium":
        if not body.password:
            return JSONResponse(
                {"detail": "password step-up required for medium-risk tool invoke"},
                status_code=400,
            )
        step_up_denied = await verify_admin_step_up(
            request,
            state=state,
            session=session,
            password=body.password,
            operation="invoke_tool",
            metadata={"tool": name, "risk": definition.risk},
        )
        if step_up_denied is not None:
            return step_up_denied

    from dataclasses import replace
    from datetime import UTC, datetime, timedelta

    from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession

    now = datetime.now(UTC)
    authenticated = AuthenticatedSession(
        session_id=session.session_id,
        identity=ActorIdentity(
            user_id=session.identity.user_id,
            agent_id="admin-ui",
            tenant_id=None,
        ),
        auth_method="service_token",
        status="active",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    tool_request = ToolRequest(
        correlation_id=f"admin_{uuid4().hex}",
        actor=Actor(user_id=session.identity.user_id, agent_id="admin-ui"),
        target=body.target,
        parameters=body.parameters,
        options=RequestOptions(dry_run=body.dry_run),
    )

    context = replace(
        state.tool_context_factory(tool_request),
        authenticated_session=authenticated,
    )
    result = await state.tool_registry.execute(name, tool_request, context)
    payload = result.model_dump(mode="json")
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.tools.invoke",
        operation="invoke",
        result_status="success" if payload.get("status") != "error" else "error",
        metadata={"invoked_tool": name, "risk": definition.risk},
    )
    return JSONResponse({"tool": name, "result": payload})


async def health_deps(request: Request) -> Response:
    state = _state(request)
    live = _build_liveness_payload(state.settings)
    ready = await _build_readiness_payload(state.settings, state.dependency_checkers)
    return JSONResponse({"live": live, "ready": ready})


async def health_doctor(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    from proxmox_mcp.server.config_validation import doctor_async

    issues = await doctor_async(state.settings)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.health.doctor",
        operation="doctor",
        result_status="success",
        metadata={"issue_count": len(issues)},
    )
    return JSONResponse(
        {
            "ok": len(issues) == 0,
            "issues": [{"name": i.name, "detail": i.detail} for i in issues],
        }
    )


async def list_approvals(request: Request) -> Response:
    state = _state(request)
    if state.approval_store is None or not hasattr(state.approval_store, "list_approvals"):
        return JSONResponse({"approvals": [], "count": 0})
    status = request.query_params.get("status")
    approvals = await state.approval_store.list_approvals(status=status, limit=100)  # type: ignore[misc]
    return JSONResponse({"approvals": approvals, "count": len(approvals)})


async def get_approval(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if state.approval_store is None or not hasattr(state.approval_store, "get_by_id"):
        return JSONResponse({"detail": "Approval store unavailable"}, status_code=503)
    approval_id = request.path_params["approval_id"]
    approval = await state.approval_store.get_by_id(approval_id)  # type: ignore[misc]
    if approval is None:
        return JSONResponse({"detail": "Approval not found"}, status_code=404)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.approvals.viewed",
        operation="view",
        result_status="success",
        metadata={"approval_request_id": approval_id},
    )
    return JSONResponse({"approval": approval})


async def decide_approval(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role != "admin":
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="decide_approval",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    if state.approval_store is None or not hasattr(state.approval_store, "decide"):
        return JSONResponse({"detail": "Approval store unavailable"}, status_code=503)
    approval_id = request.path_params["approval_id"]
    body = ApprovalDecideBody.model_validate(await request.json())
    step_up_denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="decide_approval",
        metadata={"approval_request_id": approval_id},
    )
    if step_up_denied is not None:
        return step_up_denied
    updated = await state.approval_store.decide(  # type: ignore[misc]
        approval_id,
        decision=body.decision,
        decided_by=session.identity.username,
        decided_by_user_id=session.identity.user_id,
        reason=body.reason,
    )
    if updated is None:
        return JSONResponse({"detail": "Approval not found or not pending"}, status_code=404)
    # DecideResult dataclass or legacy dict
    approval_payload: dict[str, object]
    approval_token: str | None = None
    quorum_pending = False
    error_code: str | None = None
    if hasattr(updated, "approval"):
        approval_payload = updated.approval  # type: ignore[assignment]
        approval_token = getattr(updated, "approval_token", None)
        quorum_pending = bool(getattr(updated, "quorum_pending", False))
        error_code = getattr(updated, "error_code", None)
    else:
        approval_payload = updated  # type: ignore[assignment]
    if error_code == "DUPLICATE_APPROVER":
        return JSONResponse(
            {"detail": "Same admin cannot approve twice", "approval": approval_payload},
            status_code=409,
        )
    if error_code == "SOD_VIOLATION":
        return JSONResponse(
            {
                "detail": "Separation of duty: approver cannot be the requesting actor",
                "approval": approval_payload,
            },
            status_code=403,
        )
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.approvals.decide",
        operation=body.decision,
        result_status="success",
        metadata={
            "approval_request_id": approval_id,
            "reason": body.reason,
            "token_issued": approval_token is not None,
            "quorum_pending": quorum_pending,
        },
    )
    response: dict[str, object] = {
        "approval": approval_payload,
        "approval_request_id": approval_id,
        "expires_at": approval_payload.get("expires_at"),
        "quorum_pending": quorum_pending,
    }
    if approval_token is not None:
        response["approval_token"] = approval_token
        response["retry_hint"] = (
            "Agents should retry with options.approval_request_id "
            f"({approval_id}) plus the approval_resume_secret from the "
            "original mint response — no token paste required. "
            "approval_token remains available for non-agent clients and is shown only once."
        )
    elif quorum_pending:
        response["retry_hint"] = (
            "Dual-control pending: a second distinct admin must approve before a token is issued."
        )
    return JSONResponse(response)


async def get_policy(request: Request) -> Response:
    state = _state(request)
    cfg = state.config_store.public_config()
    return JSONResponse({"dangerous_operations": cfg.get("dangerous_operations", {})})


async def put_policy(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role != "admin":
        await _write_admin_audit(
            state,
            session=session,
            tool_name="admin.authz.denied",
            operation="update_policy",
            result_status="denied",
            metadata={"reason": "role"},
        )
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    body = PolicyBody.model_validate(await request.json())
    step_up_denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="update_policy",
    )
    if step_up_denied is not None:
        return step_up_denied
    result = state.config_store.apply_config(
        AdminConfigUpdate(
            dangerous_operations_enabled=body.dangerous_operations_enabled,
            dangerous_operations_require_approval=body.dangerous_operations_require_approval,
        )
    )
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.policy.update",
        operation="update_policy",
        result_status="success",
        metadata={"changed_fields": list(result.changed_fields)},
    )
    cfg = state.config_store.public_config()
    return JSONResponse(
        {
            "result": {
                "kind": result.kind,
                "changed_fields": list(result.changed_fields),
                "message": result.message,
            },
            "dangerous_operations": cfg.get("dangerous_operations", {}),
        }
    )


class WebhookTestBody(BaseModel):
    password: str = Field(min_length=1)


async def test_approval_webhook(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role != "admin":
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    body = WebhookTestBody.model_validate(await request.json())
    denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="test_approval_webhook",
    )
    if denied is not None:
        return denied
    from proxmox_mcp.approvals.webhook import (
        build_approval_queued_payload,
        maybe_dispatch_approval_queued,
    )

    payload = build_approval_queued_payload(
        approval_request_id="test-ping",
        operation="admin.webhook.test",
        risk_level="low",
        expires_at="1970-01-01T00:00:00+00:00",
        actor_user_id=session.identity.username,
        actor_agent_id="admin-ui",
    )
    meta = await maybe_dispatch_approval_queued(settings=state.settings, payload=payload)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.approvals.webhook_test",
        operation="test",
        result_status="success" if meta.get("webhook_ok") else "error",
        metadata={k: v for k, v in meta.items() if "secret" not in k},
    )
    return JSONResponse({"ok": bool(meta.get("webhook_ok")), "delivery": meta})
