# Security Regression Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic CI security regression harness that proves the MCP control plane fails closed, preserves audit evidence, redacts sensitive values, and enforces encrypted transport assumptions.

**Architecture:** Add focused tests under `tests/security/` and keep reusable test setup local to that package. Add one small production redaction utility under `src/proxmox_mcp/security/redaction.py`, then apply it at registry response and audit boundaries. Tighten Proxmox cluster transport validation so all configured API endpoints use HTTPS, with production still requiring certificate verification.

**Tech Stack:** Python 3.13, pytest, Pydantic v2, FastMCP tool registry, existing security guard, existing settings/TLS/proxmox config models.

**Repository Safety:** Do not create git commits during execution unless the user separately asks for commits. Use verification checkpoints after each task instead.

---

## File Structure

- Create `src/proxmox_mcp/security/redaction.py`: recursive sanitizer for dictionaries, lists, tuples, Pydantic secret values, and sensitive key names.
- Modify `src/proxmox_mcp/tools/registry.py`: sanitize error details and audit metadata before crossing MCP/audit boundaries.
- Modify `src/proxmox_mcp/proxmox/config.py`: require `https://` API endpoints for every cluster environment; keep production-only TLS verification requirement.
- Create `tests/security/conftest.py`: shared request/session/context/approval fixtures for security invariant tests.
- Create `tests/security/test_security_invariants.py`: control-plane, RBAC, approval, handler non-execution, and audit transition tests.
- Create `tests/security/test_secret_redaction_invariants.py`: sanitizer and registry-boundary leak-prevention tests.
- Create `tests/security/test_transport_invariants.py`: TLS, dependency URL, and Proxmox endpoint transport tests.
- Modify `docs/security-model.md`: document CI-enforced security invariants.
- Modify `docs/release-hardening.md`: update preview release gates and current evidence.
- Modify `README.md`: update validation status after final suite count is known.

---

## Task 1: Add Test-Local Security Fixtures

**Files:**
- Create: `tests/security/conftest.py`

- [ ] **Step 1: Add shared fixtures and builders**

Create `tests/security/conftest.py`:

```python
from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import TypeAlias

from proxmox_mcp.approvals import (
    InMemoryApprovalStore,
    StoredApproval,
    canonical_json_hash,
    hash_approval_token,
)
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession, SessionStatus
from proxmox_mcp.config import DangerousOperationSettings, Settings
from proxmox_mcp.rbac import Role, RoleAssignment, Scope
from proxmox_mcp.schemas.envelope import Actor, RequestOptions, Target, ToolRequest
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolRegistry

APPROVAL_TOKEN = "approved-request-code"

Handler: TypeAlias = Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]


class HandlerSpy:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
        self.calls += 1
        return {"resource_id": request.target.resource_id, "request_id": context.request_id}


def make_request(
    *,
    approval_token: str | None = None,
    actor_user_id: str = "user_1",
    actor_agent_id: str = "agent_1",
    actor_tenant_id: str = "tenant_1",
    target_tenant_id: str = "tenant_1",
    resource_id: str = "100",
    parameters: dict[str, object] | None = None,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(
            user_id=actor_user_id,
            agent_id=actor_agent_id,
            tenant_id=actor_tenant_id,
        ),
        target=Target(
            tenant_id=target_tenant_id,
            cluster="prod",
            node="pve-1",
            resource_type="vm",
            resource_id=resource_id,
        ),
        parameters={"force": True} if parameters is None else parameters,
        options=RequestOptions(approval_token=approval_token),
    )


def make_session(
    *,
    identity: ActorIdentity | None = None,
    status: SessionStatus = "active",
) -> AuthenticatedSession:
    issued_at = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess_1",
        identity=identity
        if identity is not None
        else ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        auth_method="service_token",
        status=status,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=15),
    )


def make_context(
    request: ToolRequest,
    writer: InMemoryAuditWriter,
    *,
    dangerous_operations: DangerousOperationSettings | None = None,
    session: AuthenticatedSession | None = None,
    audit_metadata: dict[str, object] | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(
            environment="test",
            dangerous_operations=DangerousOperationSettings()
            if dangerous_operations is None
            else dangerous_operations,
        ),
        audit_writer=writer,
        authenticated_session=make_session() if session is None else session,
        audit_metadata={} if audit_metadata is None else audit_metadata,
    )


def make_delete_definition(handler: Handler) -> ToolDefinition:
    return ToolDefinition(
        name="delete_vm",
        category="vm",
        permission="vm.delete",
        risk="high",
        dry_run=False,
        approval_default=True,
        connector="proxmox_api",
        handler=handler,
    )


def make_role_assignment() -> RoleAssignment:
    return RoleAssignment(
        actor_user_id="user_1",
        actor_agent_id="agent_1",
        role=Role(name="VM Deleter", permissions=frozenset({"vm.delete"})),
        scope=Scope(tenant_id="tenant_1", resource_type="vm"),
    )


def make_approval(request: ToolRequest, *, token: str = APPROVAL_TOKEN) -> StoredApproval:
    return StoredApproval(
        approval_request_id="apr_1",
        operation="vm.delete",
        target_hash=canonical_json_hash(request.target.model_dump(mode="json")),
        input_hash=canonical_json_hash(request.parameters),
        approval_token_hash=hash_approval_token(token),
        actor_user_id=request.actor.user_id,
        actor_agent_id=request.actor.agent_id,
        actor_tenant_id=request.actor.tenant_id,
        risk_level="critical",
        risk_score=95,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        status="approved",
    )


def make_registry(
    handler: Handler,
    *,
    role_assignments: tuple[RoleAssignment, ...] = (),
    approval_store: InMemoryApprovalStore | None = None,
) -> ToolRegistry:
    registry = ToolRegistry(
        guard=SecurityPlaneGuard(
            role_assignments=role_assignments,
            approval_store=approval_store,
        )
    )
    registry.register(make_delete_definition(handler))
    return registry
```

- [ ] **Step 2: Verify fixtures import cleanly**

Run:

```powershell
python -m pytest --collect-only tests/security
```

Expected: collection succeeds. If no new tests exist yet, pytest may report the existing `tests/security/test_guard.py` collection only.

---

## Task 2: Add Control-Plane Security Invariant Tests

**Files:**
- Create: `tests/security/test_security_invariants.py`

- [ ] **Step 1: Write failing or strengthening tests for security guard invariants**

Create `tests/security/test_security_invariants.py`:

```python
from __future__ import annotations

from proxmox_mcp.approvals import InMemoryApprovalStore
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.config import DangerousOperationSettings
from proxmox_mcp.schemas.envelope import ToolErrorResponse, ToolResponse

from .conftest import (
    APPROVAL_TOKEN,
    HandlerSpy,
    make_approval,
    make_context,
    make_registry,
    make_request,
    make_role_assignment,
    make_session,
)


async def test_missing_rbac_fails_closed_without_handler_execution() -> None:
    request = make_request()
    writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    registry = make_registry(handler)

    response = await registry.execute("delete_vm", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "RBAC_DENIED"
    assert handler.calls == 0
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_forged_request_actor_uses_authenticated_identity_in_audit() -> None:
    request = make_request(actor_user_id="user_2")
    writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    registry = make_registry(handler, role_assignments=(make_role_assignment(),))

    response = await registry.execute(
        "delete_vm",
        request,
        make_context(
            request,
            writer,
            session=make_session(
                identity=ActorIdentity(
                    user_id="user_1",
                    agent_id="agent_1",
                    tenant_id="tenant_1",
                )
            ),
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "AUTHENTICATION_FAILED"
    assert handler.calls == 0
    assert [event.actor_user_id for event in writer.events] == ["user_1", "user_1"]
    assert [event.tenant_id for event in writer.events] == ["tenant_1", "tenant_1"]


async def test_dangerous_operations_disabled_fails_before_handler_execution() -> None:
    request = make_request()
    writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    registry = make_registry(handler, role_assignments=(make_role_assignment(),))

    response = await registry.execute(
        "delete_vm",
        request,
        make_context(
            request,
            writer,
            dangerous_operations=DangerousOperationSettings(enabled=False),
        ),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "DANGEROUS_OPERATION_DISABLED"
    assert handler.calls == 0
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_missing_approval_fails_before_handler_execution() -> None:
    request = make_request()
    writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    registry = make_registry(handler, role_assignments=(make_role_assignment(),))

    response = await registry.execute("delete_vm", request, make_context(request, writer))

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "APPROVAL_REQUIRED"
    assert handler.calls == 0
    assert [event.result_status for event in writer.events] == ["started", "denied"]


async def test_valid_approval_executes_once_and_replay_fails_closed() -> None:
    request = make_request(approval_token=APPROVAL_TOKEN)
    writer = InMemoryAuditWriter()
    replay_writer = InMemoryAuditWriter()
    handler = HandlerSpy()
    store = InMemoryApprovalStore((make_approval(request),))
    registry = make_registry(
        handler,
        role_assignments=(make_role_assignment(),),
        approval_store=store,
    )

    first = await registry.execute("delete_vm", request, make_context(request, writer))
    second = await registry.execute("delete_vm", request, make_context(request, replay_writer))

    assert isinstance(first, ToolResponse)
    assert first.approval.required is True
    assert handler.calls == 1
    assert [event.result_status for event in writer.events] == ["started", "success"]
    assert isinstance(second, ToolErrorResponse)
    assert second.error.code == "APPROVAL_SCOPE_MISMATCH"
    assert handler.calls == 1
    assert [event.result_status for event in replay_writer.events] == ["started", "denied"]
```

- [ ] **Step 2: Run the focused invariant tests**

Run:

```powershell
python -m pytest tests/security/test_security_invariants.py -v
```

Expected: tests pass, or fail only on an actual invariant gap. If a gap appears, fix the source before continuing.

---

## Task 3: Add Secret Redaction Utility Tests

**Files:**
- Create: `tests/security/test_secret_redaction_invariants.py`
- Create: `src/proxmox_mcp/security/redaction.py`

- [ ] **Step 1: Write redaction utility tests first**

Create `tests/security/test_secret_redaction_invariants.py` with these initial tests:

```python
from __future__ import annotations

from pydantic import SecretStr

from proxmox_mcp.security.redaction import REDACTED_VALUE, sanitize_for_security_boundary

SECRET_VALUE = "super-secret-token"
PRIVATE_KEY_PATH = "C:/certs/proxmox-mcp/private.key"


def test_sanitizer_redacts_sensitive_keys_recursively() -> None:
    payload: dict[str, object] = {
        "token_secret": SECRET_VALUE,
        "safe": "node-1",
        "nested": {
            "password": SECRET_VALUE,
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
    assert SECRET_VALUE not in str(sanitized)
    assert PRIVATE_KEY_PATH not in str(sanitized)


def test_sanitizer_redacts_pydantic_secret_values() -> None:
    sanitized = sanitize_for_security_boundary({"credential": SecretStr(SECRET_VALUE)})

    assert sanitized == {"credential": REDACTED_VALUE}
    assert SECRET_VALUE not in str(sanitized)
```

- [ ] **Step 2: Run tests to verify they fail before implementation**

Run:

```powershell
python -m pytest tests/security/test_secret_redaction_invariants.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'proxmox_mcp.security.redaction'`.

- [ ] **Step 3: Implement the redaction utility**

Create `src/proxmox_mcp/security/redaction.py`:

```python
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import SecretStr

REDACTED_VALUE = "**********"

_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "auth",
    "credential",
    "key_file",
    "password",
    "private_key",
    "secret",
    "token",
)


def sanitize_for_security_boundary(value: object) -> object:
    if isinstance(value, SecretStr):
        return REDACTED_VALUE

    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                sanitized[key_text] = REDACTED_VALUE
            else:
                sanitized[key_text] = sanitize_for_security_boundary(item)
        return sanitized

    if isinstance(value, tuple):
        return tuple(sanitize_for_security_boundary(item) for item in value)

    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [sanitize_for_security_boundary(item) for item in value]

    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)
```

- [ ] **Step 4: Run redaction utility tests**

Run:

```powershell
python -m pytest tests/security/test_secret_redaction_invariants.py -v
```

Expected: PASS for the two sanitizer tests.

---

## Task 4: Apply Redaction At Registry Boundaries

**Files:**
- Modify: `tests/security/test_secret_redaction_invariants.py`
- Modify: `src/proxmox_mcp/tools/registry.py`

- [ ] **Step 1: Add failing registry-boundary leak tests**

Append to `tests/security/test_secret_redaction_invariants.py`:

```python
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.tools.registry import ToolExecutionError

from .conftest import make_context, make_registry, make_request, make_role_assignment


async def test_tool_error_details_are_sanitized_before_response_and_audit() -> None:
    async def failing_handler(request, context):
        raise ToolExecutionError(
            error_code="PROXMOX_API_ERROR",
            message="backend rejected request",
            details={
                "token_secret": SECRET_VALUE,
                "node": "pve-1",
                "nested": {"password": SECRET_VALUE},
            },
        )

    request = make_request(approval_token=None)
    writer = InMemoryAuditWriter()
    registry = make_registry(
        failing_handler,
        role_assignments=(make_role_assignment(),),
        approval_store=None,
    )
    request.options.approval_token = None
    request.options.dry_run = True

    response = await registry.execute("delete_vm", request, make_context(request, writer))

    assert response.status == "error"
    assert response.error.details["token_secret"] == REDACTED_VALUE
    assert response.error.details["node"] == "pve-1"
    assert SECRET_VALUE not in str(response.model_dump(mode="json"))
    assert SECRET_VALUE not in str([event.model_dump(mode="json") for event in writer.events])


async def test_audit_metadata_is_sanitized_before_recording() -> None:
    async def handler(request, context):
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
                "api_token": SECRET_VALUE,
                "safe_marker": "kept",
                "nested": {"private_key_path": PRIVATE_KEY_PATH},
            },
        ),
    )

    assert response.status == "error"
    assert response.error.code == "APPROVAL_REQUIRED"
    dumped_events = [event.model_dump(mode="json") for event in writer.events]
    assert SECRET_VALUE not in str(dumped_events)
    assert PRIVATE_KEY_PATH not in str(dumped_events)
    assert dumped_events[0]["metadata"]["api_token"] == REDACTED_VALUE
    assert dumped_events[0]["metadata"]["safe_marker"] == "kept"
```

- [ ] **Step 2: Run tests to verify registry-boundary leak behavior**

Run:

```powershell
python -m pytest tests/security/test_secret_redaction_invariants.py -v
```

Expected before implementation: one or both new tests fail because registry error details or audit metadata still include raw sensitive values.

- [ ] **Step 3: Sanitize registry error details and audit metadata**

Modify `src/proxmox_mcp/tools/registry.py`.

Add import near the existing imports:

```python
from proxmox_mcp.security.redaction import sanitize_for_security_boundary
```

In denied guard responses, change:

```python
details=guard_decision.details,
```

to:

```python
details=self._sanitize_details(guard_decision.details),
```

In `ToolExecutionError` responses, change:

```python
details=exc.details,
```

to:

```python
details=self._sanitize_details(exc.details),
```

In `_write_audit_event`, change the metadata construction to sanitize context metadata:

```python
            metadata={
                "request_id": request.request_id,
                "tenant_id": tenant_id,
                "connector": definition.connector,
                "risk": definition.risk,
                "dry_run": request.options.dry_run,
                **self._sanitize_metadata(context.audit_metadata),
            },
```

Add these helper methods inside `ToolRegistry`:

```python
    def _sanitize_details(self, details: dict[str, object]) -> dict[str, object]:
        sanitized = sanitize_for_security_boundary(details)
        if not isinstance(sanitized, dict):
            return {}
        return sanitized

    def _sanitize_metadata(self, metadata: dict[str, object]) -> dict[str, object]:
        sanitized = sanitize_for_security_boundary(metadata)
        if not isinstance(sanitized, dict):
            return {}
        return sanitized
```

- [ ] **Step 4: Run redaction boundary tests**

Run:

```powershell
python -m pytest tests/security/test_secret_redaction_invariants.py -v
```

Expected: PASS.

---

## Task 5: Add Transport Security Invariants

**Files:**
- Create: `tests/security/test_transport_invariants.py`
- Modify: `src/proxmox_mcp/proxmox/config.py`

- [ ] **Step 1: Write transport invariant tests**

Create `tests/security/test_transport_invariants.py`:

```python
from __future__ import annotations

import pytest
from pydantic import SecretStr

from proxmox_mcp.config import Settings, TlsSettings
from proxmox_mcp.proxmox import ProxmoxClusterConfig
from proxmox_mcp.secrets import CredentialRef
from proxmox_mcp.server.tls import TlsConfigurationError, resolve_tls_config


def make_credential_ref() -> CredentialRef:
    return CredentialRef(
        provider="development",
        path="secret/proxmox/lab/api-token",
        purpose="proxmox_api",
    )


def test_proxmox_cluster_endpoint_requires_https_in_all_environments() -> None:
    with pytest.raises(ValueError, match="https"):
        ProxmoxClusterConfig(
            cluster_id="lab-pve",
            name="Lab PVE",
            api_endpoint="http://pve.example.test:8006/api2/json",
            credential_ref=make_credential_ref(),
            environment="development",
        )


def test_production_cluster_still_requires_tls_verification() -> None:
    with pytest.raises(ValueError, match="TLS"):
        ProxmoxClusterConfig(
            cluster_id="prod-pve",
            name="Production PVE",
            api_endpoint="https://pve.example.test:8006/api2/json",
            tls_verify=False,
            credential_ref=make_credential_ref(),
            environment="production",
        )


def test_database_and_redis_urls_fail_closed_without_tls() -> None:
    with pytest.raises(ValueError, match="PostgreSQL TLS"):
        Settings(database_url=SecretStr("postgresql+asyncpg://user:pass@db/app"))

    with pytest.raises(ValueError, match="Redis TLS"):
        Settings(redis_url=SecretStr("redis://redis.example:6379/0"))


def test_tls_runtime_requires_material_when_generation_is_disabled() -> None:
    with pytest.raises(TlsConfigurationError, match="certificate and key"):
        resolve_tls_config(TlsSettings(generate_self_signed=False))
```

- [ ] **Step 2: Run transport invariant tests and confirm endpoint test fails**

Run:

```powershell
python -m pytest tests/security/test_transport_invariants.py -v
```

Expected before implementation: `test_proxmox_cluster_endpoint_requires_https_in_all_environments` fails because development clusters currently allow plaintext HTTP.

- [ ] **Step 3: Enforce HTTPS for every Proxmox cluster environment**

Modify `src/proxmox_mcp/proxmox/config.py`.

Replace `_validate_production_transport` with:

```python
    @model_validator(mode="after")
    def _validate_transport(self) -> Self:
        if not self.api_endpoint.startswith("https://"):
            raise ValueError("Proxmox clusters require https:// API endpoints")

        if self.environment == "production" and not self.tls_verify:
            raise ValueError("Production Proxmox clusters require TLS verification")

        return self
```

- [ ] **Step 4: Run transport and cluster config tests**

Run:

```powershell
python -m pytest tests/security/test_transport_invariants.py tests/proxmox/test_cluster_config.py -v
```

Expected: PASS.

---

## Task 6: Run Focused Security Verification

**Files:**
- No code changes unless focused verification exposes a real gap.

- [ ] **Step 1: Run focused security suite**

Run:

```powershell
python -m pytest tests/security tests/approvals tests/policy tests/secrets tests/test_config.py tests/server/test_tls.py -v
```

Expected: all selected tests pass.

- [ ] **Step 2: Run static checks before docs**

Run:

```powershell
python -m ruff format .
python -m ruff check .
python -m pyright
```

Expected: formatting clean, ruff passes, pyright reports `0 errors`.

---

## Task 7: Update Security Documentation

**Files:**
- Modify: `docs/security-model.md`
- Modify: `docs/release-hardening.md`
- Modify: `README.md`

- [ ] **Step 1: Update `docs/security-model.md`**

Add a section near the existing security controls:

```markdown
## CI-Enforced Security Invariants

The security regression harness under `tests/security/` runs without live Proxmox credentials and proves these control-plane invariants:

- Non-internal tools fail closed when authentication, actor binding, RBAC, policy, dangerous-operation settings, or approval validation fails.
- Denied calls do not execute handlers and still emit audit evidence.
- Successful approval-gated calls emit `started` then `success` audit transitions.
- Approval tokens are scoped to actor, tenant, target, payload, operation, and risk, and are consumed once.
- Secret-like values and TLS private key paths are sanitized before MCP error responses and audit metadata are recorded.
- MCP, Proxmox, PostgreSQL, and Redis transport settings reject plaintext configurations.

These tests are not a substitute for lab validation, but they prevent regressions in the security control plane before any tool reaches live infrastructure.
```

- [ ] **Step 2: Update `docs/release-hardening.md` evidence**

Change preview release gates so the list includes:

```markdown
4. Security invariant regression suite for auth, RBAC, policy, approvals, audit evidence, redaction, and transport enforcement.
5. Docker image build.
6. Dependency vulnerability audit and SBOM generation.
7. Lab-only SSH, chaos, and performance gates when Proxmox lab credentials are configured.
```

Update current evidence after the final full-suite count is known. Use the exact observed output from Task 8.

- [ ] **Step 3: Update `README.md` validation section**

Add or update the validation bullets with:

```markdown
- Dedicated security invariant suite covering fail-closed guard behavior, approval replay protection, audit evidence, redaction boundaries, and encrypted transport enforcement.
```

Update the offline suite count after Task 8.

---

## Task 8: Full Verification

**Files:**
- No code changes unless verification exposes a real issue.

- [ ] **Step 1: Run full verification**

Run:

```powershell
python -m ruff format .
python -m ruff check .
python -m pyright
python -m pytest
```

Expected:

- Ruff format leaves files unchanged or reformats only files changed in this plan.
- Ruff check passes.
- Pyright reports `0 errors`.
- Pytest passes with lab tests skipped unless lab environment variables are configured.

- [ ] **Step 2: Read lints for edited files**

Use the IDE linter check for:

- `src/proxmox_mcp/security/redaction.py`
- `src/proxmox_mcp/tools/registry.py`
- `src/proxmox_mcp/proxmox/config.py`
- `tests/security/conftest.py`
- `tests/security/test_security_invariants.py`
- `tests/security/test_secret_redaction_invariants.py`
- `tests/security/test_transport_invariants.py`

Expected: no introduced linter errors.

- [ ] **Step 3: Final status check**

Run:

```powershell
git status --short --branch
```

Expected: only intended source, test, and documentation files are modified or added.

---

## Plan Self-Review

- Spec coverage: the plan covers deterministic CI security tests, fail-closed behavior, approval replay/scope, audit evidence, redaction, encrypted transport, and documentation updates.
- Scope check: no live Proxmox mutation, no guarded tool promotion, and no new auth/policy/secret backends are included.
- Type consistency: helper builders use existing `ToolRequest`, `ToolExecutionContext`, `ToolDefinition`, `InMemoryApprovalStore`, `Settings`, and `ProxmoxClusterConfig` APIs.
- Placeholder scan: no task contains open-ended implementation placeholders; documentation evidence count is intentionally tied to exact final test output from Task 8.
