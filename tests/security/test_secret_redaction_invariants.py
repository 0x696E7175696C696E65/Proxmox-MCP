from __future__ import annotations

from pydantic import SecretStr

from proxmox_mcp.approvals import InMemoryApprovalStore
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.schemas.envelope import ToolErrorResponse, ToolRequest
from proxmox_mcp.security.redaction import REDACTED_VALUE, sanitize_for_security_boundary
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolExecutionError
from tests.security.helpers import (
    APPROVAL_CODE,
    make_approval,
    make_context,
    make_registry,
    make_request,
    make_role_assignment,
)

LEAK_MARKER = "super-redaction-marker"
PRIVATE_KEY_PATH = "C:/certs/proxmox-mcp/private.key"


def test_sanitizer_redacts_sensitive_keys_recursively() -> None:
    payload: dict[str, object] = {
        "token_secret": LEAK_MARKER,
        "safe": "node-1",
        "nested": {
            "password": LEAK_MARKER,
            "items": [{"private_key_path": PRIVATE_KEY_PATH}],
        },
    }

    sanitized = sanitize_for_security_boundary(payload)

    assert sanitized == {
        "token_secret": REDACTED_VALUE,
        "safe": "node-1",
        "nested": {
            "password": REDACTED_VALUE,
            "items": [{"private_key_path": REDACTED_VALUE}],
        },
    }
    assert LEAK_MARKER not in str(sanitized)
    assert PRIVATE_KEY_PATH not in str(sanitized)


def test_sanitizer_redacts_pydantic_secret_values() -> None:
    sanitized = sanitize_for_security_boundary({"credential": SecretStr(LEAK_MARKER)})

    assert sanitized == {"credential": REDACTED_VALUE}
    assert LEAK_MARKER not in str(sanitized)


async def test_tool_error_details_are_sanitized_before_response_and_audit() -> None:
    async def failing_handler(
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> dict[str, object]:
        raise ToolExecutionError(
            error_code="PROXMOX_API_ERROR",
            message="backend rejected request",
            details={
                "token_secret": LEAK_MARKER,
                "node": "pve-1",
                "nested": {"password": LEAK_MARKER},
            },
        )

    request = make_request(approval_token=APPROVAL_CODE)
    writer = InMemoryAuditWriter()
    registry = make_registry(
        failing_handler,
        role_assignments=(make_role_assignment(),),
        approval_store=InMemoryApprovalStore((make_approval(request),)),
    )

    response = await registry.execute("delete_vm", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.details["token_secret"] == REDACTED_VALUE
    assert response.error.details["node"] == "pve-1"
    assert LEAK_MARKER not in str(response.model_dump(mode="json"))
    assert LEAK_MARKER not in str([event.model_dump(mode="json") for event in writer.events])


async def test_audit_metadata_is_sanitized_before_recording() -> None:
    async def handler(
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> dict[str, object]:
        return {"ok": True}

    request = make_request()
    writer = InMemoryAuditWriter()
    registry = make_registry(
        handler,
        role_assignments=(make_role_assignment(),),
    )

    response = await registry.execute(
        "delete_vm",
        request,
        make_context(
            request,
            writer,
            audit_metadata={
                "api_token": LEAK_MARKER,
                "safe_marker": "kept",
                "nested": {"private_key_path": PRIVATE_KEY_PATH},
            },
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "APPROVAL_REQUIRED"
    dumped_events = [event.model_dump(mode="json") for event in writer.events]
    assert LEAK_MARKER not in str(dumped_events)
    assert PRIVATE_KEY_PATH not in str(dumped_events)
    assert dumped_events[0]["metadata"]["api_token"] == REDACTED_VALUE
    assert dumped_events[0]["metadata"]["safe_marker"] == "kept"
