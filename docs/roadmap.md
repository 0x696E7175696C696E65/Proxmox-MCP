# Implementation Roadmap

## Status Model

- `implemented`: code and deterministic tests exist in the repository.
- `lab_validated`: implementation has been exercised against a disposable Proxmox lab.
- `production_qualified`: implementation has HA, compatibility, migration, rollback, chaos, and release evidence for production use.
- `guarded`: cataloged behavior exists but live execution is intentionally blocked until the promotion checklist is complete.

## Milestone 0: Architecture Package

Status: implemented.

Deliverables:

- Architecture document.
- Threat model.
- Security model.
- Tool specification.
- MCP schema.
- Database schema.
- Testing strategy.
- Deployment guide.
- CI pipeline definition.

Exit criteria:

- No unresolved placeholders.
- Tool catalog exceeds 100 tools and is grouped by domain.
- Security, policy, audit, approval, and dangerous operation behavior are explicit.
- User approves moving into runtime implementation.

## Milestone 1: Foundation Runtime

Status: implemented.

Deliverables:

- Python 3.13 project scaffold.
- FastMCP server entrypoint.
- Pydantic v2 settings and schemas.
- Structured logging.
- Health endpoints.
- PostgreSQL SQLAlchemy models and Alembic migrations.
- Redis client and cache abstractions.
- Correlation ID middleware.
- Audit event writer.
- Basic CI for lint, typing, tests, and security checks.

Exit criteria:

- Server starts locally.
- Health checks pass.
- Database migrations run.
- A sample no-op MCP tool produces audit events.

## Milestone 2: Auth, RBAC, Policy, And Secrets

Status: implemented for service-token auth, RBAC, policy, approvals, development secrets, and Vault-style secrets. OIDC, mTLS caller auth, workload identity, and additional secret backends remain planned integrations.

Deliverables:

- Caller authentication abstraction.
- API token or service-token auth for first release.
- RBAC model and evaluator.
- Policy parser and decision engine.
- Built-in roles.
- Secret manager abstraction.
- Development secret backend.
- Hashicorp Vault adapter.
- Approval data model.

Exit criteria:

- Deny policies override allow policies.
- Approval policies return structured `APPROVAL_REQUIRED`.
- Secret values are not logged or persisted.
- Unit tests cover decision ordering.

## Milestone 3: Read-Only Proxmox Coverage

Status: implemented and partially lab_validated.

Deliverables:

- Proxmoxer connector and connection pool.
- Cluster discovery.
- Node inventory and status.
- VM and LXC listing.
- Storage listing.
- Network and firewall read tools.
- Backup and snapshot read tools.
- Ceph status read tools.
- User and permission read tools.
- Monitoring read tools.

Exit criteria:

- Read-only tools run against a Proxmox lab.
- Results use normalized response schemas.
- API retries and circuit breakers are covered by tests.

## Milestone 4: Safe Mutations And AI Safety

Status: implemented with dry-run, risk, approval, audit, and selected disposable lab validation.

Deliverables:

- Dry-run support.
- Impact analysis service.
- Change preview service.
- Risk scoring engine.
- Idempotency records.
- Safe lifecycle actions for VM and LXC start, stop, shutdown, reboot, snapshot, backup, and restore.
- Rollback suggestion generation.

Exit criteria:

- High-risk operations return previews in dry-run mode.
- Idempotency prevents duplicate mutation.
- Audit events include risk and impact metadata.

## Milestone 5: Dangerous Operations And Approvals

Status: implemented with policy, approval, target revalidation, and audit controls. Destructive production use remains guarded by environment-specific lab validation.

Deliverables:

- Configurable dangerous operation registry.
- Approval request lifecycle.
- Approval token validation.
- Target revalidation before execution.
- Destructive VM, LXC, storage, Ceph, node, and firewall operations.
- Policy-driven bypass for trusted lab environments.

Exit criteria:

- Dangerous operations can be enabled, denied, or approval-gated by policy.
- Approval replay is rejected.
- Destructive operations produce pre-execution and post-execution audit events.

## Milestone 6: Controlled SSH Subsystem

Status: implemented for command execution, policy, sessions, file transfer, recording references, and redaction. Production multi-replica interactive session behavior remains constrained until sticky-session or broker strategy is validated.

Deliverables:

- AsyncSSH connector.
- Non-interactive command execution.
- Interactive session support.
- SFTP and SCP.
- File upload and download.
- Command policy evaluator.
- Session recording.
- Timeout, rate limit, and concurrent session controls.
- SSH audit redaction.

Exit criteria:

- SSH permissions are separate from API permissions.
- Arbitrary shell execution requires explicit policy.
- Session recordings are referenced in audit events.
- Command failures return structured errors.

## Milestone 7: Full Proxmox Domain Coverage

Status: implemented for most read, mutation, dangerous, and domain-pack paths. Backend-specific or source-dependent tools remain guarded until lab evidence and exact contracts exist.

Deliverables:

- Complete VM and LXC hardware management.
- Storage creation, deletion, expansion, benchmark, ZFS, LVM, LVM-thin, NFS, SMB, Ceph, and directory storage operations.
- Bridge, bond, VLAN, SDN, and VXLAN management.
- Datacenter, node, and VM firewall management.
- Backup schedule, verification, retention, and restore management.
- HA resources and groups.
- User, group, role, and permission mutations.

Exit criteria:

- Each shipped tool has schema, permission metadata, audit coverage, and tests.
- Tool catalog implementation coverage is tracked.

## Milestone 8: Observability And Integrations

Status: implemented for in-process metrics, structured logs, trace context, audit correlation, and dashboard examples. Queryable audit, alerts, trends, and durable SIEM delivery remain production-readiness work.

Deliverables:

- Prometheus metrics endpoint.
- OpenTelemetry traces.
- Structured JSON logs.
- Loki-friendly log format.
- SIEM exporters for Splunk, ELK, Graylog, and Wazuh.
- Grafana dashboard examples.

Exit criteria:

- Operators can trace a tool call from MCP request to Proxmox task and audit event.
- Metrics expose tool latency, policy outcomes, connector health, SSH sessions, and Proxmox task failures.

## Milestone 9: Production Deployment And HA

Status: partially implemented at deployment-manifest level. Runtime shared-state correctness, dependency-aware readiness, distributed idempotency, and multi-replica approval/session behavior remain active work.

Deliverables:

- Docker image.
- Docker Compose deployment.
- Kubernetes manifests or Helm chart.
- Horizontal server replicas.
- PostgreSQL and Redis HA guidance.
- Network policies.
- Secrets backend examples.
- Backup and restore runbooks.
- Upgrade runbooks.

Exit criteria:

- Multiple MCP server replicas run safely with shared PostgreSQL and Redis.
- Approval and idempotency workflows work across replicas.
- Deployment docs include hardening and recovery guidance.

## Milestone 10: Hardening And Compatibility

Status: in progress. CI, distribution, SBOM, security invariants, and hardening scaffolds exist; migration gates, image scanning, compatibility matrix, chaos/load evidence, and release enforcement remain active work.

Deliverables:

- Proxmox version compatibility matrix.
- Chaos tests for node failure, quorum loss, network interruption, API failures, and SSH failures.
- Security scanning and SBOM generation.
- Load tests.
- Migration tests.
- Release process.

Exit criteria:

- The platform is ready for tagged preview release.
- Known limitations are documented.
- Upgrade and rollback are tested.
