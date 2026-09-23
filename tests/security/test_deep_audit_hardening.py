"""Regression tests for deep-audit secure-by-design patches."""

from __future__ import annotations

import ipaddress

import pytest

from proxmox_mcp.rbac import RBACEvaluator, Role, RoleAssignment, Scope
from proxmox_mcp.risk import DangerousOperationRegistry
from proxmox_mcp.security.egress import validate_https_url_host
from proxmox_mcp.security.redaction import sanitize_for_security_boundary
from proxmox_mcp.auth import ActorIdentity


def test_cluster_admin_denies_wipe_and_power() -> None:
    role = Role.cluster_admin()
    actor = ActorIdentity(user_id="u", agent_id="a")
    evaluator = RBACEvaluator()
    assignments = (
        RoleAssignment(role=role, scope=Scope(), actor_user_id="u", actor_agent_id="a"),
    )
    assert evaluator.is_allowed(actor, "vm.config.read", _target(), assignments)
    assert not evaluator.is_allowed(actor, "storage.disk.wipe", _target(), assignments)
    assert not evaluator.is_allowed(actor, "node.power.reboot", _target(), assignments)
    assert not evaluator.is_allowed(actor, "firewall.config.write", _target(), assignments)
    assert not evaluator.is_allowed(actor, "ssh.command.execute", _target(), assignments)


def test_admin_console_never_star() -> None:
    role = Role.admin_console()
    assert "*" not in role.permissions
    assert not RBACEvaluator()._role_allows(role, "ssh.file.download")


def test_dangerous_registry_includes_disable_firewall() -> None:
    registry = DangerousOperationRegistry.default()
    assert "disable_firewall" in registry.critical_operations
    assert "firewall.config.write" in registry.critical_operations


def test_egress_blocks_metadata_and_loopback() -> None:
    with pytest.raises(ValueError):
        validate_https_url_host(
            "https://169.254.169.254/latest",
            allow_private=False,
            allow_public=True,
        )
    with pytest.raises(ValueError):
        validate_https_url_host(
            "https://127.0.0.1/x",
            allow_private=True,
            allow_public=True,
        )


def test_redaction_passthrough_keeps_approval_resume_secret() -> None:
    from proxmox_mcp.security.redaction import sanitize_for_security_boundary

    agent_facing = sanitize_for_security_boundary(
        {
            "approval_request_id": "apr_1",
            "approval_resume_secret": "real-once-secret",
            "token": "should-hide",
            "nested": {"service_token": "hide-me"},
        },
        allow_agent_capabilities=True,
    )
    assert isinstance(agent_facing, dict)
    assert agent_facing["approval_resume_secret"] == "real-once-secret"
    assert agent_facing["token"] == "**********"
    nested = agent_facing["nested"]
    assert isinstance(nested, dict)
    assert nested["service_token"] == "**********"

    # Audit / SSE / SIEM must never retain the resume secret.
    audit_facing = sanitize_for_security_boundary(
        {
            "approval_request_id": "apr_1",
            "approval_resume_secret": "real-once-secret",
        },
        allow_agent_capabilities=False,
    )
    assert isinstance(audit_facing, dict)
    assert audit_facing["approval_resume_secret"] == "**********"
    assert audit_facing["approval_request_id"] == "apr_1"


def test_egress_blocks_cgnat_and_alibaba_imds() -> None:
    with pytest.raises(ValueError):
        validate_https_url_host(
            "https://100.100.100.200/latest/meta-data",
            allow_private=False,
            allow_public=True,
        )
    with pytest.raises(ValueError):
        validate_https_url_host(
            "https://100.64.1.1/x",
            allow_private=True,
            allow_public=True,
        )


def test_egress_allows_private_for_homelab_hosts() -> None:
    endpoint = validate_https_url_host(
        "https://192.168.1.10:8006/api2/json/version",
        allow_private=True,
        allow_public=False,
    )
    assert endpoint.hostname == "192.168.1.10"
    assert ipaddress.ip_address(endpoint.addresses[0]).is_private


def test_redaction_covers_cipassword_and_sshkeys() -> None:
    sanitized = sanitize_for_security_boundary(
        {"cipassword": "secret", "sshkeys": "ssh-rsa AAAA", "name": "vm"}
    )
    assert isinstance(sanitized, dict)
    assert sanitized["cipassword"] == "**********"
    assert sanitized["sshkeys"] == "**********"
    assert sanitized["name"] == "vm"


def _target():
    from proxmox_mcp.rbac import AccessTarget

    return AccessTarget(resource_type="vm", resource_id="100")
