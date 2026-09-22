from __future__ import annotations

from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.rbac import AccessTarget, RBACEvaluator, Role, RoleAssignment, Scope


def test_rbac_allows_only_matching_scope() -> None:
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1")
    role = Role(name="VM Starter", permissions=frozenset({"vm.lifecycle.start"}))
    assignments = (
        RoleAssignment(
            actor_user_id="user_1",
            role=role,
            scope=Scope(
                tenant_id="tenant_1",
                clusters=frozenset({"prod"}),
                nodes=frozenset({"pve-1"}),
                resource_type="vm",
                resource_ids=frozenset({"100"}),
            ),
        ),
    )
    evaluator = RBACEvaluator()

    assert evaluator.is_allowed(
        actor,
        "vm.lifecycle.start",
        AccessTarget(
            tenant_id="tenant_1",
            cluster="prod",
            node="pve-1",
            resource_type="vm",
            resource_id="100",
        ),
        assignments,
    )
    assert not evaluator.is_allowed(
        actor,
        "vm.lifecycle.start",
        AccessTarget(
            tenant_id="tenant_1",
            cluster="prod",
            node="pve-2",
            resource_type="vm",
            resource_id="100",
        ),
        assignments,
    )


def test_custom_role_permission_is_honored() -> None:
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1")
    assignments = (
        RoleAssignment(
            actor_user_id="user_1",
            role=Role(name="Console Viewer", permissions=frozenset({"vm.console.read"})),
            scope=Scope(resource_type="vm"),
        ),
    )

    assert RBACEvaluator().is_allowed(
        actor,
        "vm.console.read",
        AccessTarget(resource_type="vm", resource_id="101"),
        assignments,
    )


def test_tenant_scoped_role_requires_actor_and_target_tenant_match() -> None:
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1")
    assignments = (
        RoleAssignment(
            role=Role(name="Tenant VM Reader", permissions=frozenset({"vm.read"})),
            scope=Scope(tenant_id="tenant_1", resource_type="vm"),
        ),
    )
    evaluator = RBACEvaluator()

    assert evaluator.is_allowed(
        actor,
        "vm.read",
        AccessTarget(tenant_id="tenant_1", resource_type="vm", resource_id="100"),
        assignments,
    )
    assert not evaluator.is_allowed(
        actor,
        "vm.read",
        AccessTarget(tenant_id="tenant_2", resource_type="vm", resource_id="100"),
        assignments,
    )
    assert not evaluator.is_allowed(
        actor,
        "vm.read",
        AccessTarget(resource_type="vm", resource_id="100"),
        assignments,
    )


def test_read_only_role_does_not_allow_mutation() -> None:
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1")
    assignments = (
        RoleAssignment(
            actor_user_id="user_1",
            role=Role.read_only(),
            scope=Scope(resource_type="vm"),
        ),
    )
    target = AccessTarget(resource_type="vm", resource_id="101")
    evaluator = RBACEvaluator()

    assert evaluator.is_allowed(actor, "vm.read", target, assignments)
    assert not evaluator.is_allowed(actor, "vm.lifecycle.start", target, assignments)


def test_vm_permission_does_not_imply_ssh_permission() -> None:
    actor = ActorIdentity(user_id="user_1", agent_id="agent_1")
    assignments = (
        RoleAssignment(
            actor_user_id="user_1",
            role=Role(name="VM Operator", permissions=frozenset({"vm.lifecycle.*"})),
            scope=Scope(resource_type="vm"),
        ),
    )

    assert not RBACEvaluator().is_allowed(
        actor,
        "ssh.execute",
        AccessTarget(resource_type="node", resource_id="pve-1", node="pve-1"),
        assignments,
    )


def test_scope_supports_vmid_ranges_and_storage_ids() -> None:
    scope = Scope(
        resource_type="vm",
        vmid_min=100,
        vmid_max=199,
        storage_ids=frozenset({"local-zfs"}),
    )

    assert scope.matches(
        ActorIdentity(user_id="user_1", agent_id="agent_1"),
        AccessTarget(resource_type="vm", resource_id="150", storage_id="local-zfs"),
    )
    assert not scope.matches(
        ActorIdentity(user_id="user_1", agent_id="agent_1"),
        AccessTarget(resource_type="vm", resource_id="250", storage_id="local-zfs"),
    )
