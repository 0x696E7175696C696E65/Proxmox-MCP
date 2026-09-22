# MCP Schema

## Design Goals

The MCP schema should make infrastructure actions predictable for AI agents and safe for operators. All tools share common envelopes for identity, target resolution, dry-run behavior, risk, approval, errors, pagination, and audit correlation.

## Common Request Envelope

```json
{
  "request_id": "req_01HY...",
  "actor": {
    "user_id": "user_123",
    "agent_id": "agent_claude_ops",
    "tenant_id": "tenant_prod"
  },
  "target": {
    "cluster": "prod-pve",
    "node": "pve-a",
    "resource_type": "vm",
    "resource_id": "104"
  },
  "options": {
    "dry_run": true,
    "explain_plan": true,
    "include_impact_analysis": true,
    "idempotency_key": "idem_01HY...",
    "approval_token": null,
    "timeout_seconds": 120
  },
  "parameters": {}
}
```

`parameters` is tool-specific. The rest of the envelope is shared by all tools.

## Common Response Envelope

```json
{
  "request_id": "req_01HY...",
  "correlation_id": "corr_01HY...",
  "status": "success",
  "dry_run": true,
  "risk": {
    "level": "critical",
    "score": 95,
    "reasons": ["destructive_operation", "backup_chain_affected"]
  },
  "policy": {
    "decision": "requires_approval",
    "matched_rules": ["prod-dangerous-vm-delete"]
  },
  "approval": {
    "required": true,
    "approval_request_id": "appr_01HY...",
    "expires_at": "2026-06-05T23:59:00Z"
  },
  "impact": {
    "affected_resources": ["vm/104", "storage/local-lvm/vm-104-disk-0"],
    "estimated_downtime_seconds": null,
    "data_loss_possible": true
  },
  "result": {},
  "warnings": [],
  "rollback_suggestions": [],
  "audit": {
    "event_id": "audit_01HY...",
    "recorded": true
  }
}
```

## Error Envelope

```json
{
  "request_id": "req_01HY...",
  "correlation_id": "corr_01HY...",
  "status": "error",
  "error": {
    "code": "POLICY_DENIED",
    "message": "Policy denied vm.lifecycle.destroy on vm/104.",
    "retryable": false,
    "details": {
      "matched_rules": ["deny-prod-vm-delete"]
    }
  },
  "audit": {
    "event_id": "audit_01HY...",
    "recorded": true
  }
}
```

## Error Codes

- `INVALID_REQUEST`
- `AUTHENTICATION_REQUIRED`
- `AUTHENTICATION_FAILED`
- `SESSION_EXPIRED`
- `RBAC_DENIED`
- `POLICY_DENIED`
- `APPROVAL_REQUIRED`
- `APPROVAL_EXPIRED`
- `APPROVAL_SCOPE_MISMATCH`
- `DANGEROUS_OPERATION_DISABLED`
- `SECRET_UNAVAILABLE`
- `PROXMOX_API_ERROR`
- `PROXMOX_TASK_FAILED`
- `SSH_CONNECTION_FAILED`
- `SSH_COMMAND_FAILED`
- `SSH_POLICY_DENIED`
- `RATE_LIMITED`
- `CIRCUIT_OPEN`
- `AUDIT_WRITE_FAILED`
- `TIMEOUT`
- `CONFLICT`
- `NOT_FOUND`
- `INTERNAL_ERROR`

## Risk Schema

```json
{
  "level": "high",
  "score": 72,
  "reasons": [
    "mutating_operation",
    "service_restart",
    "production_scope"
  ],
  "dangerous_operation": false
}
```

Risk level mapping:

- `low`: read-only or local inspection.
- `medium`: reversible routine changes.
- `high`: service-impacting or broad-scope mutations.
- `critical`: destructive, data-loss, quorum, network-lockout, or arbitrary-shell risk.

## Impact Analysis Schema

```json
{
  "affected_resources": [
    {
      "type": "vm",
      "id": "104",
      "node": "pve-a",
      "name": "postgres-prod"
    }
  ],
  "dependencies": [
    {
      "type": "backup_chain",
      "id": "pbs:vm/104"
    }
  ],
  "estimated_downtime_seconds": 300,
  "data_loss_possible": false,
  "network_disruption_possible": false,
  "quorum_risk": false,
  "rollback_available": true,
  "rollback_suggestions": [
    "Rollback to snapshot pre-maintenance-20260605 if startup fails."
  ]
}
```

## Approval Request Schema

```json
{
  "approval_request_id": "appr_01HY...",
  "operation": "delete_vm",
  "target_hash": "sha256:...",
  "input_hash": "sha256:...",
  "actor": {
    "user_id": "user_123",
    "agent_id": "agent_claude_ops"
  },
  "risk": {
    "level": "critical",
    "score": 95
  },
  "impact": {},
  "expires_at": "2026-06-05T23:59:00Z",
  "status": "pending"
}
```

Approvals are valid only for the same operation, target, input hash, actor, risk profile, and expiration window.

## Pagination Schema

Read tools that can return large collections support:

```json
{
  "pagination": {
    "limit": 100,
    "cursor": "eyJvZmZzZXQiOjEwMH0="
  }
}
```

Responses include:

```json
{
  "items": [],
  "pagination": {
    "next_cursor": null,
    "has_more": false
  }
}
```

## Idempotency Schema

Mutating tools accept `idempotency_key`. The server stores the first result for the tuple:

- Tenant.
- Actor.
- Tool name.
- Target.
- Input hash.
- Idempotency key.

Conflicting reuse returns `CONFLICT`.

## SSH Command Schema

```json
{
  "target": {
    "cluster": "prod-pve",
    "node": "pve-a"
  },
  "parameters": {
    "command": "zpool status -x",
    "shell": "/bin/bash",
    "working_directory": "/root",
    "environment": {},
    "timeout_seconds": 30,
    "capture_stdout": true,
    "capture_stderr": true,
    "redaction_profile": "default"
  },
  "options": {
    "dry_run": true,
    "include_impact_analysis": true
  }
}
```

## Audit Event Schema

```json
{
  "event_id": "audit_01HY...",
  "correlation_id": "corr_01HY...",
  "timestamp": "2026-06-05T22:30:00Z",
  "event_type": "tool.execution.finished",
  "actor_user_id": "user_123",
  "actor_agent_id": "agent_claude_ops",
  "tenant_id": "tenant_prod",
  "tool_name": "delete_vm",
  "operation": "vm.lifecycle.destroy",
  "target": {
    "cluster": "prod-pve",
    "node": "pve-a",
    "resource_type": "vm",
    "resource_id": "104"
  },
  "policy_decision": "approved",
  "approval_request_id": "appr_01HY...",
  "result_status": "success",
  "exit_code": 0,
  "duration_ms": 4812,
  "redacted": true
}
```

## Versioning

Tool schemas use semantic versions. Breaking request or response changes require a new tool version or compatibility adapter. Audit schemas are append-only; fields may be added but existing fields should not be renamed or removed.
