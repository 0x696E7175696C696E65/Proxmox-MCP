"""Admin Access APIs: capability roles, tool catalog for ACL, effective access."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxmox_mcp.admin.app import _state, _write_admin_audit, verify_admin_step_up
from proxmox_mcp.admin.auth import get_admin_session
from proxmox_mcp.rbac.capability import CapabilityRole
from proxmox_mcp.rbac.store import CapabilityRoleStore, resolve_system_role_id


class RoleCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    granted_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    base_template: str | None = None
    allow_star: bool = False
    password: str = Field(min_length=1)


class RoleUpdateBody(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    granted_tools: list[str] | None = None
    denied_tools: list[str] | None = None
    allow_star: bool = False
    password: str = Field(min_length=1)


class RoleDeleteBody(BaseModel):
    password: str = Field(min_length=1)


class EffectiveAccessBody(BaseModel):
    user_id: str | None = None
    capability_role_id: str | None = None
    tool_name: str | None = None


def _role_public(role: CapabilityRole) -> dict[str, object]:
    return {
        "role_id": role.role_id,
        "name": role.name,
        "description": role.description,
        "base_template": role.base_template,
        "granted_tools": sorted(role.granted_tools),
        "denied_tools": sorted(role.denied_tools),
        "permission_seeds": sorted(role.permission_seeds),
        "system": role.system,
        "version": role.version,
        "grant_count": role.grant_count(),
    }


def _store(request: Request) -> CapabilityRoleStore | None:
    state = _state(request)
    store = getattr(state, "capability_role_store", None)
    if store is not None:
        return store
    factory = getattr(getattr(state, "identity_provider", None), "_session_factory", None)
    if factory is None:
        return None
    return CapabilityRoleStore(factory)


def _require_admin(session: Any) -> Response | None:
    if session.identity.role != "admin":
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    return None


async def list_capability_roles(request: Request) -> Response:
    session = get_admin_session()
    assert session is not None
    denied = _require_admin(session)
    if denied is not None:
        return denied
    store = _store(request)
    if store is None:
        return JSONResponse({"roles": [], "count": 0})
    await _ensure_seeded(request, store)
    roles = await store.list_roles()
    return JSONResponse({"roles": [_role_public(r) for r in roles], "count": len(roles)})


async def _ensure_seeded(request: Request, store: CapabilityRoleStore) -> None:
    state = _state(request)
    registry = getattr(state, "tool_registry", None)
    if registry is None:
        await store.ensure_system_roles(tool_names=[], tool_permissions={}, tool_risks={})
        return
    definitions = list(registry.definitions())
    await store.ensure_system_roles(
        tool_names=[d.name for d in definitions],
        tool_permissions={d.name: d.permission for d in definitions},
        tool_risks={d.name: d.risk for d in definitions},
    )


async def get_capability_role(request: Request) -> Response:
    session = get_admin_session()
    assert session is not None
    denied = _require_admin(session)
    if denied is not None:
        return denied
    store = _store(request)
    if store is None:
        return JSONResponse({"detail": "Role store unavailable"}, status_code=503)
    role = await store.get(request.path_params["role_id"])
    if role is None:
        return JSONResponse({"detail": "Role not found"}, status_code=404)
    return JSONResponse({"role": _role_public(role)})


async def create_capability_role(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin(session)
    if denied is not None:
        return denied
    body = RoleCreateBody.model_validate(await request.json())
    step = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="create_capability_role",
        metadata={"name": body.name},
    )
    if step is not None:
        return step
    store = _store(request)
    if store is None:
        return JSONResponse({"detail": "Role store unavailable"}, status_code=503)
    actor_role = await _actor_capability(store, session)
    try:
        created = await store.create(
            name=body.name,
            description=body.description,
            granted_tools=body.granted_tools,
            denied_tools=body.denied_tools,
            base_template=body.base_template,
            allow_star=body.allow_star,
        )
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    if actor_role is not None and not created.is_subset_of(actor_role):
        await store.delete(created.role_id)
        return JSONResponse(
            {"detail": "Cannot create a role broader than your own grants (anti-escalation)"},
            status_code=403,
        )
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.access.roles.create",
        operation="create",
        result_status="success",
        metadata={"role_id": created.role_id, "name": created.name},
    )
    return JSONResponse({"role": _role_public(created)}, status_code=201)


async def update_capability_role(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin(session)
    if denied is not None:
        return denied
    role_id = request.path_params["role_id"]
    body = RoleUpdateBody.model_validate(await request.json())
    step = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="update_capability_role",
        metadata={"role_id": role_id},
    )
    if step is not None:
        return step
    store = _store(request)
    if store is None:
        return JSONResponse({"detail": "Role store unavailable"}, status_code=503)
    actor_role = await _actor_capability(store, session)
    try:
        updated = await store.update(
            role_id,
            name=body.name,
            description=body.description,
            granted_tools=body.granted_tools,
            denied_tools=body.denied_tools,
            allow_star=body.allow_star,
        )
    except LookupError:
        return JSONResponse({"detail": "Role not found"}, status_code=404)
    except PermissionError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    if actor_role is not None and not updated.is_subset_of(actor_role):
        return JSONResponse(
            {"detail": "Cannot assign grants broader than your own (anti-escalation)"},
            status_code=403,
        )
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.access.roles.update",
        operation="update",
        result_status="success",
        metadata={"role_id": role_id},
    )
    return JSONResponse({"role": _role_public(updated)})


async def delete_capability_role(request: Request) -> Response:
    state = _state(request)
    session = get_admin_session()
    assert session is not None
    denied = _require_admin(session)
    if denied is not None:
        return denied
    role_id = request.path_params["role_id"]
    body = RoleDeleteBody.model_validate(await request.json())
    step = await verify_admin_step_up(
        request,
        state=state,
        session=session,
        password=body.password,
        operation="delete_capability_role",
        metadata={"role_id": role_id},
    )
    if step is not None:
        return step
    store = _store(request)
    if store is None:
        return JSONResponse({"detail": "Role store unavailable"}, status_code=503)
    try:
        await store.delete(role_id)
    except LookupError:
        return JSONResponse({"detail": "Role not found"}, status_code=404)
    except PermissionError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
    await _write_admin_audit(
        state,
        session=session,
        tool_name="admin.access.roles.delete",
        operation="delete",
        result_status="success",
        metadata={"role_id": role_id},
    )
    return JSONResponse({"ok": True, "role_id": role_id})


async def tool_catalog_for_acl(request: Request) -> Response:
    """Tool catalog shaped for Access role editor (grouped by connector/risk)."""
    session = get_admin_session()
    assert session is not None
    denied = _require_admin(session)
    if denied is not None:
        return denied
    state = _state(request)
    if state.tool_registry is None:
        return JSONResponse({"tools": [], "count": 0, "groups": {}})
    tools = []
    groups: dict[str, list[str]] = {
        "read": [],
        "mutate": [],
        "dangerous": [],
        "ssh": [],
        "admin": [],
        "other": [],
    }
    for definition in state.tool_registry.definitions():
        item = {
            "name": definition.name,
            "description": definition.description,
            "category": definition.category,
            "permission": definition.permission,
            "risk": definition.risk,
            "connector": definition.connector,
        }
        tools.append(item)
        bucket = "other"
        if definition.connector == "ssh" or definition.name.startswith("ssh_"):
            bucket = "ssh"
        elif definition.risk in {"high", "critical"} or definition.approval_default:
            bucket = "dangerous"
        elif definition.risk == "medium" or "lifecycle" in definition.permission:
            bucket = "mutate"
        elif definition.risk == "low" or definition.permission.endswith(".read"):
            bucket = "read"
        if definition.name.startswith("admin.") or definition.connector == "internal":
            if definition.name != "health_check":
                bucket = "admin"
        groups.setdefault(bucket, []).append(definition.name)
    tools.sort(key=lambda t: str(t["name"]))
    return JSONResponse({"tools": tools, "count": len(tools), "groups": groups})


async def effective_access(request: Request) -> Response:
    session = get_admin_session()
    assert session is not None
    denied = _require_admin(session)
    if denied is not None:
        return denied
    body = EffectiveAccessBody.model_validate(await request.json())
    store = _store(request)
    if store is None:
        return JSONResponse({"detail": "Role store unavailable"}, status_code=503)
    role: CapabilityRole | None = None
    if body.capability_role_id:
        role = await store.get(body.capability_role_id)
    elif body.user_id:
        from sqlalchemy import select

        from proxmox_mcp.persistence.models import AdminUserRecord

        factory = getattr(getattr(_state(request), "identity_provider", None), "_session_factory", None)
        if factory is None:
            return JSONResponse({"detail": "User store unavailable"}, status_code=503)
        async with factory() as db:
            user = await db.get(AdminUserRecord, body.user_id)
            if user is None:
                return JSONResponse({"detail": "User not found"}, status_code=404)
            role_id = user.capability_role_id or resolve_system_role_id(user.role)
            role = await store.get(role_id)
    if role is None:
        return JSONResponse({"detail": "Capability role not found"}, status_code=404)
    allowed = True
    if body.tool_name:
        allowed = role.allows_tool(body.tool_name)
    return JSONResponse(
        {
            "role": _role_public(role),
            "tool_name": body.tool_name,
            "allowed": allowed if body.tool_name else None,
        }
    )


async def _actor_capability(store: CapabilityRoleStore, session: Any) -> CapabilityRole | None:
    coarse = getattr(session.identity, "role", "admin") or "admin"
    return await store.get(resolve_system_role_id(str(coarse)))
