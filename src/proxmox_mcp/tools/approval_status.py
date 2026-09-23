"""MCP tools for actor-scoped approval status (never returns tokens)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolRegistry


class ApprovalStatusParams(BaseModel):
    approval_request_id: str = Field(min_length=1)


class ListMyApprovalsParams(BaseModel):
    status: str | None = None
    limit: int = Field(default=50, ge=1, le=200)


def _actor_matches(row: dict[str, object], context: ToolExecutionContext) -> bool:
    return (
        str(row.get("actor_user_id") or "") == context.actor.user_id
        and str(row.get("actor_agent_id") or "") == context.actor.agent_id
    )


def _status_row(row: dict[str, object]) -> dict[str, object]:
    return {
        "approval_request_id": row.get("approval_request_id"),
        "operation": row.get("operation"),
        "status": row.get("status"),
        "risk_level": row.get("risk_level"),
        "expires_at": row.get("expires_at"),
        "decided_by": row.get("decided_by"),
        "decided_at": row.get("decided_at"),
        "required_approvals": row.get("required_approvals", 1),
        "approval_count": row.get("approval_count", 0),
    }


async def _list_my_pending_approvals(
    request: ToolRequest,
    context: ToolExecutionContext,
) -> object:
    _ = request
    store = context.approval_store
    if store is None or not hasattr(store, "list_approvals"):
        return {"approvals": [], "count": 0}
    params = ListMyApprovalsParams.model_validate(request.parameters or {})
    rows = await store.list_approvals(status=params.status or "pending", limit=params.limit)
    mine = [_status_row(row) for row in rows if _actor_matches(row, context)]
    context.audit_metadata["approval_status_list_count"] = len(mine)
    return {"approvals": mine, "count": len(mine)}


async def _get_approval_status(
    request: ToolRequest,
    context: ToolExecutionContext,
) -> object:
    store = context.approval_store
    if store is None or not hasattr(store, "get_by_id"):
        return {"found": False, "error_code": "APPROVAL_STORE_UNAVAILABLE"}
    params = ApprovalStatusParams.model_validate(request.parameters or {})
    row = await store.get_by_id(params.approval_request_id)
    if row is None or not _actor_matches(row, context):
        context.audit_metadata["approval_status_denied"] = True
        return {"found": False, "error_code": "NOT_FOUND"}
    context.audit_metadata["approval_request_id"] = params.approval_request_id
    return {"found": True, "approval": _status_row(row)}


def register_approval_status_tools(registry: ToolRegistry) -> None:
    registry.register(
        ToolDefinition(
            name="list_my_pending_approvals",
            description=(
                "List pending approval requests minted for the current actor. "
                "Never returns approval tokens."
            ),
            category="approval",
            permission="approval.status.read",
            risk="low",
            dry_run=False,
            approval_default=False,
            connector="internal",
            handler=_list_my_pending_approvals,
            parameters_model=ListMyApprovalsParams,
            result_model=None,
        )
    )
    registry.register(
        ToolDefinition(
            name="get_approval_status",
            description=(
                "Get status for an approval_request_id owned by the current actor. "
                "Never returns approval tokens."
            ),
            category="approval",
            permission="approval.status.read",
            risk="low",
            dry_run=False,
            approval_default=False,
            connector="internal",
            handler=_get_approval_status,
            parameters_model=ApprovalStatusParams,
            result_model=None,
        )
    )
