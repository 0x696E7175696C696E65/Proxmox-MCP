"""Admin user management APIs (admin-only + step-up)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field
from sqlalchemy import select
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxmox_mcp.admin.app import _state, _write_admin_audit, verify_admin_step_up
from proxmox_mcp.admin.auth import get_admin_session
from proxmox_mcp.admin.auth.passwords import hash_password
from proxmox_mcp.persistence.models.admin import AdminUserRecord

AdminRoleBody = Literal["admin", "operator", "viewer"]


class CreateUserBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    user_password: str = Field(min_length=8, max_length=256)
    role: AdminRoleBody = "operator"
    capability_role_id: str | None = None
    password: str = Field(min_length=1)


class UpdateUserBody(BaseModel):
    role: AdminRoleBody | None = None
    capability_role_id: str | None = None
    disabled: bool | None = None
    user_password: str | None = Field(default=None, min_length=8, max_length=256)
    password: str = Field(min_length=1)


def _user_public(record: AdminUserRecord) -> dict[str, object]:
    return {
        "user_id": record.user_id,
        "username": record.username,
        "role": record.role,
        "capability_role_id": getattr(record, "capability_role_id", None),
        "disabled": record.disabled_at is not None,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "last_login_at": None if record.last_login_at is None else record.last_login_at.isoformat(),
    }


async def list_users(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role != "admin":
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    provider = state.identity_provider
    factory = getattr(provider, "_session_factory", None)
    if factory is None:
        return JSONResponse({"users": [], "count": 0})
    async with factory() as db:
        statement = select(AdminUserRecord).order_by(AdminUserRecord.username.asc())
        records = list((await db.scalars(statement)).all())
    return JSONResponse({"users": [_user_public(r) for r in records], "count": len(records)})


async def create_user(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role != "admin":
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    body = CreateUserBody.model_validate(await request.json())
    denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="create_user",
        metadata={"username": body.username, "role": body.role},
    )
    if denied is not None:
        return denied
    factory = getattr(state.identity_provider, "_session_factory", None)
    if factory is None:
        return JSONResponse({"detail": "User store unavailable"}, status_code=503)
    async with factory() as db:
        existing = (
            await db.scalars(
                select(AdminUserRecord).where(AdminUserRecord.username == body.username)
            )
        ).first()
        if existing is not None:
            return JSONResponse({"detail": "Username already exists"}, status_code=409)
        record = AdminUserRecord(
            user_id=f"adminuser_{uuid4().hex}",
            username=body.username,
            password_hash=hash_password(body.user_password),
            role=body.role,
            capability_role_id=body.capability_role_id,
            created_at=datetime.now(UTC),
            last_login_at=None,
            disabled_at=None,
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.users.create",
        operation="create",
        result_status="success",
        metadata={"username": body.username, "role": body.role},
    )
    return JSONResponse({"user": _user_public(record)}, status_code=201)


async def update_user(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    if session.identity.role != "admin":
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    user_id = request.path_params["user_id"]
    body = UpdateUserBody.model_validate(await request.json())
    denied = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="update_user",
        metadata={"user_id": user_id},
    )
    if denied is not None:
        return denied
    factory = getattr(state.identity_provider, "_session_factory", None)
    if factory is None:
        return JSONResponse({"detail": "User store unavailable"}, status_code=503)
    async with factory() as db:
        record = await db.get(AdminUserRecord, user_id)
        if record is None:
            return JSONResponse({"detail": "User not found"}, status_code=404)
        if body.role is not None:
            record.role = body.role
        if "capability_role_id" in body.model_fields_set:
            record.capability_role_id = body.capability_role_id
        if body.disabled is True:
            record.disabled_at = datetime.now(UTC)
        elif body.disabled is False:
            record.disabled_at = None
        if body.user_password is not None:
            record.password_hash = hash_password(body.user_password)
        await db.commit()
        await db.refresh(record)
    # Privilege/password changes must invalidate existing sessions immediately.
    if (
        body.role is not None
        or "capability_role_id" in body.model_fields_set
        or body.disabled is True
        or body.user_password is not None
    ):
        revoke = getattr(state.identity_provider, "revoke_user_sessions", None)
        if callable(revoke):
            await revoke(user_id)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.users.update",
        operation="update",
        result_status="success",
        metadata={
            "user_id": user_id,
            "role": body.role,
            "capability_role_id": body.capability_role_id,
            "disabled": body.disabled,
        },
    )
    return JSONResponse({"user": _user_public(record)})
