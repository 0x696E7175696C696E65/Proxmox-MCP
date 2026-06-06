# Enterprise Proxmox MCP Server

Enterprise Proxmox MCP is a production-oriented Model Context Protocol server design for secure AI-assisted Proxmox VE administration. The project goal is to expose Proxmox API and controlled SSH capabilities to AI agents while preserving strong authorization, policy enforcement, approval workflows, auditability, and operational guardrails.

This repository is intentionally not a thin wrapper around Proxmox. It is designed as an infrastructure automation platform suitable for homelabs, MSPs, datacenters, research labs, and advanced automation environments.

## Current Status

The repository is in the architecture and planning milestone. Runtime implementation will follow the staged roadmap in `docs/roadmap.md` after review of the design package.

## Primary Capabilities

- Manage clusters, nodes, VMs, LXC containers, storage, networking, firewall, backups, HA, Ceph, users, and permissions.
- Execute controlled SSH operations for shell commands, interactive sessions, SFTP, SCP, upload, and download.
- Enforce RBAC, policy rules, dangerous operation controls, approvals, dry-run behavior, impact analysis, and risk scoring.
- Emit structured audit logs, metrics, traces, and SIEM-ready events.
- Support enterprise secret backends including Hashicorp Vault, Bitwarden Secrets Manager, 1Password Connect, AWS Secrets Manager, and Azure Key Vault.

## Intended Stack

- Python 3.13+
- FastMCP
- AsyncSSH
- Proxmoxer
- Pydantic v2
- SQLAlchemy
- PostgreSQL
- Redis
- OpenTelemetry
- Prometheus metrics

## Documentation

- `docs/architecture.md`: system architecture, module boundaries, and runtime flows.
- `docs/security-model.md`: authentication, authorization, policy, approvals, and dangerous operations.
- `docs/threat-model.md`: assets, trust boundaries, abuse cases, and mitigations.
- `docs/tool-specification.md`: 100+ MCP tool catalog.
- `docs/mcp-schema.md`: request, response, error, dry-run, impact, and audit schemas.
- `docs/database-schema.md`: persistence model for sessions, policy, audit, approvals, credentials, resources, and SSH recordings.
- `docs/roadmap.md`: staged implementation plan.
- `docs/testing-strategy.md`: verification strategy from unit tests through Proxmox lab tests and chaos testing.
- `docs/deployment.md`: Docker, Kubernetes, HA, observability, and operations guide.

## Safety Posture

Dangerous operations are supported but never treated as ordinary tool calls. Destructive actions can be enabled, denied, or routed through approval workflows by policy. Every execution path must produce auditable evidence, including actor, AI agent identity, target resource, policy decision, command or API operation, result, exit code, and correlation identifiers.

## Repository Remote

Origin is intended to be:

```text
https://github.com/0x696E7175696C696E65/Proxmox-MCP.git
```
