from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Protocol

import pytest

from proxmox_mcp.approvals import ApprovalValidationResult
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.auth import ActorIdentity, AuthenticatedSession
from proxmox_mcp.config import Settings
from proxmox_mcp.policy import PolicyEngine, PolicyRule
from proxmox_mcp.proxmox import register_read_only_tools, register_safe_mutation_tools
from proxmox_mcp.proxmox.http_client import ProxmoxHttpApiClient
from proxmox_mcp.proxmox.lab import LabEnvironmentConfig
from proxmox_mcp.rbac import Role, RoleAssignment, Scope
from proxmox_mcp.reliability import ProxmoxTaskStore
from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.security import SecurityPlaneGuard
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolRegistry

LAB_APPROVAL_CODE = "lab-" + "approved"


class LabToolContextFactory(Protocol):
    def __call__(
        self,
        request: ToolRequest,
        lab_client: ProxmoxHttpApiClient,
        audit_writer: InMemoryAuditWriter,
        *,
        authenticated: bool = True,
        proxmox_task_store: ProxmoxTaskStore | None = None,
    ) -> ToolExecutionContext: ...


class LabApprovalConsumer:
    def consume(self, approval_token: str | None, **_: object) -> ApprovalValidationResult:
        if approval_token != LAB_APPROVAL_CODE:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")
        return ApprovalValidationResult(valid=True)


@pytest.fixture(scope="session")
def lab_config() -> LabEnvironmentConfig:
    config = LabEnvironmentConfig.from_env(os.environ)
    if not config.enabled:
        pytest.skip(config.skip_reason or "Proxmox lab tests are not enabled")
    return config


@pytest.fixture(scope="session")
def lab_client(lab_config: LabEnvironmentConfig) -> ProxmoxHttpApiClient:
    if lab_config.api_endpoint is None:
        pytest.skip("Missing Proxmox lab API endpoint")
    if lab_config.auth_mode == "api_token":
        if lab_config.token_id is None or lab_config.token_secret is None:
            pytest.skip("Missing Proxmox lab API token")

        return ProxmoxHttpApiClient(
            api_endpoint=lab_config.api_endpoint,
            token_id=lab_config.token_id,
            token_secret=lab_config.token_secret,
            tls_verify=lab_config.tls_verify,
        )

    if lab_config.username is None or lab_config.password is None:
        pytest.skip("Missing Proxmox lab username/password credentials")

    return ProxmoxHttpApiClient(
        api_endpoint=lab_config.api_endpoint,
        username=lab_config.username,
        password=lab_config.password,
        tls_verify=lab_config.tls_verify,
    )


@pytest.fixture
def optional_lab_node(lab_config: LabEnvironmentConfig) -> Iterator[str]:
    if lab_config.node is None:
        pytest.skip("Set PROXMOX_MCP_LAB_NODE to run node-scoped lab smoke tests")
    yield lab_config.node


@pytest.fixture
def optional_lab_storage(lab_config: LabEnvironmentConfig) -> Iterator[str]:
    if lab_config.storage_id is None:
        pytest.skip("Set PROXMOX_MCP_LAB_STORAGE to run storage-scoped lab smoke tests")
    yield lab_config.storage_id


@pytest.fixture
def lab_mutations_enabled(lab_config: LabEnvironmentConfig) -> bool:
    _ = lab_config
    if os.environ.get("PROXMOX_MCP_LAB_MUTATIONS_ENABLED", "").strip().lower() != "true":
        pytest.skip("Set PROXMOX_MCP_LAB_MUTATIONS_ENABLED=true to run mutation lab tests")
    return True


@pytest.fixture
def lab_destructive_enabled(lab_mutations_enabled: bool) -> bool:
    _ = lab_mutations_enabled
    if os.environ.get("PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED", "").strip().lower() != "true":
        pytest.skip("Set PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED=true to run destructive lab tests")
    return True


@pytest.fixture
def disposable_lab_vmid(lab_destructive_enabled: bool) -> int:
    _ = lab_destructive_enabled
    raw_vmid = os.environ.get("PROXMOX_MCP_LAB_TEST_VMID")
    if raw_vmid is None:
        pytest.skip("Set PROXMOX_MCP_LAB_TEST_VMID to an explicit disposable VMID")
    try:
        return int(raw_vmid)
    except ValueError:
        pytest.skip("PROXMOX_MCP_LAB_TEST_VMID must be an integer")


@pytest.fixture
def disposable_lab_ctid(lab_destructive_enabled: bool) -> int:
    _ = lab_destructive_enabled
    raw_ctid = os.environ.get("PROXMOX_MCP_LAB_TEST_CTID")
    if raw_ctid is None:
        pytest.skip("Set PROXMOX_MCP_LAB_TEST_CTID to an explicit disposable CTID")
    try:
        return int(raw_ctid)
    except ValueError:
        pytest.skip("PROXMOX_MCP_LAB_TEST_CTID must be an integer")


@pytest.fixture
def lab_audit_writer() -> InMemoryAuditWriter:
    return InMemoryAuditWriter()


@pytest.fixture
def lab_actor_identity() -> ActorIdentity:
    return ActorIdentity(user_id="lab_user", agent_id="lab_agent", tenant_id="lab_tenant")


@pytest.fixture
def lab_authenticated_session(lab_actor_identity: ActorIdentity) -> AuthenticatedSession:
    issued_at = datetime.now(UTC)
    return AuthenticatedSession(
        session_id="sess_lab",
        identity=lab_actor_identity,
        auth_method="service_token",
        status="active",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=15),
    )


@pytest.fixture
def lab_read_role_assignment(
    lab_actor_identity: ActorIdentity,
    lab_config: LabEnvironmentConfig,
) -> RoleAssignment:
    return RoleAssignment(
        actor_user_id=lab_actor_identity.user_id,
        actor_agent_id=lab_actor_identity.agent_id,
        role=Role(name="Lab Read Operator", permissions=frozenset({"*"})),
        scope=Scope(
            tenant_id=lab_actor_identity.tenant_id,
            clusters=frozenset({lab_config.cluster_id}),
        ),
    )


@pytest.fixture
def lab_read_tool_registry(lab_read_role_assignment: RoleAssignment) -> ToolRegistry:
    registry = ToolRegistry(guard=SecurityPlaneGuard(role_assignments=(lab_read_role_assignment,)))
    register_read_only_tools(registry)
    return registry


@pytest.fixture
def lab_unauthorized_read_tool_registry() -> ToolRegistry:
    registry = ToolRegistry(guard=SecurityPlaneGuard(role_assignments=()))
    register_read_only_tools(registry)
    return registry


@pytest.fixture
def lab_policy_denied_read_tool_registry(
    lab_read_role_assignment: RoleAssignment,
) -> ToolRegistry:
    registry = ToolRegistry(
        guard=SecurityPlaneGuard(
            role_assignments=(lab_read_role_assignment,),
            policy_engine=PolicyEngine(
                rules=(
                    PolicyRule(
                        rule_id="deny-lab-node-inventory",
                        effect="deny",
                        operations=("node.inventory.read",),
                        tenant_id="lab_tenant",
                        resource_type="cluster",
                    ),
                )
            ),
        )
    )
    register_read_only_tools(registry)
    return registry


@pytest.fixture
def lab_mutation_tool_registry(lab_read_role_assignment: RoleAssignment) -> ToolRegistry:
    registry = ToolRegistry(
        guard=SecurityPlaneGuard(
            role_assignments=(lab_read_role_assignment,),
            approval_store=LabApprovalConsumer(),
        )
    )
    register_safe_mutation_tools(registry)
    return registry


@pytest.fixture
def lab_tool_context_factory(
    lab_authenticated_session: AuthenticatedSession,
) -> LabToolContextFactory:
    def make_context(
        request: ToolRequest,
        lab_client: ProxmoxHttpApiClient,
        audit_writer: InMemoryAuditWriter,
        *,
        authenticated: bool = True,
        proxmox_task_store: ProxmoxTaskStore | None = None,
    ) -> ToolExecutionContext:
        return ToolExecutionContext(
            request=request,
            settings=Settings(environment="test"),
            audit_writer=audit_writer,
            authenticated_session=lab_authenticated_session if authenticated else None,
            proxmox_client=lab_client,
            proxmox_task_store=proxmox_task_store,
        )

    return make_context
