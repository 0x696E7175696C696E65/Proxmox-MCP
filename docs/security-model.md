# Security Model

## Principles

- Fail closed for authentication, authorization, policy, approval, audit, and secret errors.
- Prefer Proxmox API operations over SSH when equivalent functionality exists.
- Support dangerous operations through configurable controls instead of prohibiting them globally.
- Store secret references, not raw secrets.
- Produce audit evidence before and after every execution attempt.
- Separate human identity, AI agent identity, Proxmox credential identity, and runtime session identity.

## Authentication Methods

### MCP Caller Authentication

The MCP server authenticates callers before exposing tool execution. Supported caller identity modes:

- Static service token for single-tenant deployments.
- OAuth or OIDC bearer tokens for enterprise deployments.
- mTLS for trusted internal automation networks.
- Signed workload identity tokens for agent platforms.

### Proxmox Authentication

Supported Proxmox authentication modes:

- API tokens.
- Username and password with ticket handling.
- Credential references loaded from secret backends.

API tokens are preferred for automation because they are scoped, revocable, and auditable in Proxmox.

### SSH Authentication

Supported SSH authentication modes:

- ED25519 keys.
- RSA keys.
- ECDSA keys.
- Hardware-backed keys when exposed through an SSH agent or compatible signing provider.
- Secret-backed private keys.

SSH credentials are always selected through policy and resource scope. A caller with VM permissions does not automatically receive SSH permissions.

## Secret Management

The application stores credential metadata and backend references:

```yaml
credential_ref:
  provider: hashicorp_vault
  path: secret/proxmox/prod/api-token
  version: 7
  purpose: proxmox_api
  rotation_required_after: 2026-09-01T00:00:00Z
```

Supported backends:

- Hashicorp Vault.
- Bitwarden Secrets Manager.
- 1Password Connect.
- AWS Secrets Manager.
- Azure Key Vault.
- Local encrypted development provider for non-production use.

Secret rotation is modeled as metadata plus backend-specific adapters. The runtime must support overlapping old and new credential versions during rotation windows.

## Built-In Roles

### ReadOnly

Can inspect inventory, status, metrics, logs allowed by policy, backups, snapshots, storage, networking, firewall rules, and Ceph status. Cannot mutate resources or execute SSH commands unless a custom policy grants read-only commands.

### Operator

Can perform routine lifecycle actions such as VM start, stop, reboot, shutdown, snapshot, backup, restore to approved targets, and non-destructive diagnostics.

### Administrator

Can create and modify VMs, LXC containers, storage definitions, networks, firewall rules, backup jobs, HA resources, users, and permissions within assigned scopes. Dangerous operations may still require approval.

### ClusterAdmin

Can administer cluster-wide settings, nodes, Ceph, HA, datacenter firewall, user permissions, and destructive actions when policy allows.

### Custom Roles

Custom roles are named bundles of permissions and constraints. They can restrict by node, resource pool, VM ID range, storage ID, network zone, tag, environment, time window, and operation category.

## Permission Domains

Permissions are structured as `domain.resource.action`:

- `cluster.status.read`
- `cluster.config.write`
- `node.power.reboot`
- `node.package.update`
- `vm.lifecycle.start`
- `vm.lifecycle.destroy`
- `vm.hardware.write`
- `lxc.lifecycle.create`
- `storage.volume.delete`
- `network.bridge.create`
- `firewall.rule.write`
- `backup.job.create`
- `ceph.osd.remove`
- `user.permission.write`
- `ssh.command.execute`
- `ssh.file.upload`

Resource scopes bind permissions to targets:

```yaml
scope:
  datacenter: prod-dc
  nodes:
    - pve-a
    - pve-b
  vmid_range:
    min: 100
    max: 299
  storage:
    - fast-zfs
    - backup-nfs
```

## Policy Evaluation

Policy evaluation happens after RBAC. Deny rules always win. Approval rules win over allow rules unless the operation is already denied.

Decision order:

1. Validate tool schema.
2. Resolve actor, session, agent, and target resource.
3. Check RBAC permission.
4. Apply explicit deny policies.
5. Apply approval policies.
6. Apply allow policies.
7. Apply dangerous operation configuration.
8. Emit decision audit event.

Example:

```yaml
allow:
  - vm.start
  - vm.stop
  - vm.snapshot
deny:
  - cluster.destroy
  - storage.delete
require_approval:
  - node.reboot
  - node.shutdown
  - vm.destroy
```

## Dangerous Operations

Dangerous operations are configurable by environment:

```yaml
dangerous_operations:
  enabled: true
  require_approval: true
  log_full_command: true
  require_impact_analysis: true
  require_dry_run_when_supported: true
  require_target_revalidation: true
```

Default dangerous operations:

- Destroy VM.
- Destroy LXC.
- Delete datastore.
- Wipe disk.
- Remove Ceph OSD.
- Reboot node.
- Shutdown node.
- Shutdown cluster.
- Force migration.
- Execute arbitrary shell command.
- Modify datacenter firewall default policy.
- Delete backup chain.
- Remove user or permission grants.

## Approval Workflows

Approval modes:

- None: allowed immediately after policy.
- Single human approval.
- Multi-party approval.
- Break-glass approval with reason capture.
- Time-bound preapproval for maintenance windows.

Approval records include:

- Requested action.
- Requesting user and AI agent.
- Risk score.
- Impact analysis.
- Dry-run output when available.
- Approver identity.
- Expiration.
- Replay-protection token.

## AI Safety Controls

AI-facing tools should support:

- `dry_run`.
- `explain_plan`.
- `impact_analysis`.
- `change_preview`.
- `risk_score`.
- `rollback_suggestion`.
- `idempotency_key`.
- `approval_request`.

Critical operations should return a structured preview before execution when called in dry-run mode:

```json
{
  "action": "delete_vm",
  "target": "vm-104",
  "risk": "critical",
  "affected_resources": ["vm-104", "backup-chain"],
  "requires_approval": true,
  "rollback_suggestion": "Restore from latest verified backup before deleting backup chain."
}
```

## SSH Command Policy

SSH execution supports both allow-list and deny-list modes. Production deployments should prefer allow-list mode for common diagnostics and maintenance actions.

Policy inputs:

- Command executable.
- Arguments.
- Target node.
- Working directory.
- Environment variables.
- User context.
- Session type.
- Interactive or non-interactive mode.
- Output redaction profile.

Arbitrary shell commands are supported only when policy explicitly allows them.

## Audit Requirements

Every action logs:

- User identity.
- AI agent identity.
- Session ID.
- Correlation ID.
- Timestamp.
- Tool name.
- Operation category.
- Node.
- Resource.
- Command or API endpoint.
- Policy decision.
- Approval record.
- Result.
- Exit code or API status.
- Duration.
- Error class.

Sensitive values must be redacted before log persistence and SIEM forwarding.
