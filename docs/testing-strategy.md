# Testing Strategy

## Goals

Testing must prove that the server is safe, reliable, observable, and compatible with real Proxmox environments. Tests should cover both normal administration workflows and failure modes such as policy denial, approval replay, API failure, SSH timeout, node failure, and audit persistence failure.

## Test Layers

### Unit Tests

Unit tests cover pure logic:

- Pydantic schema validation.
- RBAC permission resolution.
- Policy decision ordering.
- Dangerous operation classification.
- Risk scoring.
- Impact analysis helpers.
- Audit redaction.
- Idempotency key behavior.
- Secret reference parsing.
- Error mapping.

### Contract Tests

Contract tests lock MCP schemas and tool metadata:

- Request envelope compatibility.
- Response envelope compatibility.
- Error envelope compatibility.
- Tool permission metadata.
- Risk and approval metadata.
- Pagination and idempotency behavior.

### Integration Tests

Integration tests run against local services:

- PostgreSQL migrations.
- SQLAlchemy repositories.
- Redis rate limiting and distributed locks.
- Secret backend development provider.
- Audit event persistence.
- Alertmanager alert normalization.
- Prometheus resource trend normalization.
- SIEM retry and dead-letter queue behavior.
- Approval lifecycle.
- Circuit breaker state.

### Proxmox Lab Tests

Lab tests run against a dedicated Proxmox VE environment:

- Cluster, node, VM, LXC, storage, network, backup, firewall, Ceph, and user read tools.
- Safe VM and LXC lifecycle operations.
- Snapshot, backup, restore, and migration flows.
- Storage and network change previews.
- Proxmox task polling and error handling.

Lab tests must never target production clusters.

The MCP server runtime itself is HTTPS-only. For local or disposable lab runs that
start the MCP app directly, either point the app at user-provided certificate
paths or enable generated self-signed certificates:

```shell
PROXMOX_MCP_SERVER_PORT=8443
PROXMOX_MCP_TLS__GENERATE_SELF_SIGNED=true
PROXMOX_MCP_TLS__GENERATED_CERT_DIR=/tmp/proxmox-mcp/certs
PROXMOX_MCP_TLS__COMMON_NAME=localhost
PROXMOX_MCP_TLS__SUBJECT_ALT_NAMES='["localhost","127.0.0.1"]'
```

Clients and test harnesses must trust the configured or generated certificate
when connecting to the MCP endpoint.

Application dependencies must also use encrypted transports. `Settings` rejects
PostgreSQL URLs that do not require TLS and Redis URLs that do not use
`rediss://`. External Alertmanager and Prometheus URLs must use `https://`.

Phase 1 lab tests are read-only and skip unless explicitly enabled. Configure:

- `PROXMOX_MCP_LAB_ENABLED=true`
- `PROXMOX_MCP_LAB_API_ENDPOINT=https://pve.example.test:8006`
- `PROXMOX_MCP_LAB_TOKEN_ID=user@realm!token` and `PROXMOX_MCP_LAB_TOKEN_SECRET=...`
  for token auth, or `PROXMOX_MCP_LAB_USERNAME=user@realm` and
  `PROXMOX_MCP_LAB_PASSWORD=...` for disposable lab ticket auth.
- `PROXMOX_MCP_LAB_TLS_VERIFY=true` or `false` for disposable labs with self-signed TLS
- `PROXMOX_MCP_LAB_ALLOW_INSECURE_TRANSPORT=true` if TLS verification is disabled in a disposable lab
- `PROXMOX_MCP_LAB_NODE=pve-node-1` for node-scoped discovery
- `PROXMOX_MCP_LAB_STORAGE=local` for storage-content discovery
- `PROXMOX_MCP_LAB_PROFILE=pve-9-single-node-no-ceph` to record the active
  compatibility profile. Supported profile names are documented in
  `docs/proxmox-compatibility.md`.
- `PROXMOX_MCP_LAB_LXC_TEMPLATE_STORAGE` and `PROXMOX_MCP_LAB_LXC_TEMPLATE_VOLID`
  when disposable LXC lifecycle tests should use a known template.
- `PROXMOX_MCP_LAB_LXC_TEMPLATE_NAME`,
  `PROXMOX_MCP_LAB_LXC_TEMPLATE_BOOTSTRAP_ENABLED=true`, and
  `PROXMOX_MCP_LAB_HELPER_SCRIPTS_ENABLED=true` only when the disposable lab
  should prepare a missing template through the allowlisted Proxmox API path.
- `PROXMOX_MCP_LAB_EXPECTED_STORAGE_IDS=local,local-lvm` when preflight should
  assert multiple storage IDs.
- `PROXMOX_MCP_LAB_EVIDENCE_DIR=release-evidence` for generated sanitized lab
  evidence.
- `PROXMOX_MCP_LAB_EXPECTED_NODE_COUNT=2` or higher for `pve-9-multi-node`.
- `PROXMOX_MCP_LAB_PBS_REPOSITORY=<storage-id>` for `pve-9-pbs-enabled`.

Username/password ticket-auth labs must use realm-qualified usernames such as
`root@pam`. Disposable Proxmox VE 9.1.1 validation currently records a
single-node `pve-9-storage-local-local-lvm` profile with node `test`, storage
`local` and `local-lvm`, full gated lab coverage of `20 passed, 8 skipped`, and
validated disposable VM lifecycle, registered VM update, backup create/list,
restore-precondition dry-run, storage benchmark preview, and node update
preflight evidence. Skips are expected for PBS, Ceph, HA, multi-node, and LXC
lifecycle prerequisites in this lab profile.

Run read-only lab smoke tests with:

```shell
python scripts/lab_preflight.py --output-file release-evidence/lab-preflight.json
python -m pytest tests/lab -m lab
```

If the enable flag or required credentials are missing, the suite reports skipped tests rather than failures. Phase 1 smoke coverage exercises cluster status, nodes, VM/LXC inventory, node storage, storage content, access users/roles/ACLs, HA status, cluster firewall options, and Ceph status when Ceph is installed.

Mutation and destructive lab tests require separate explicit opt-in:

- `PROXMOX_MCP_LAB_MUTATIONS_ENABLED=true`
- `PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED=true`
- `PROXMOX_MCP_LAB_TEST_VMID=<explicit disposable VMID>` for VM mutation,
  backup, and registered VM lifecycle tests
- `PROXMOX_MCP_LAB_TEST_CTID=<explicit disposable CTID>` for LXC lifecycle
  tests when an LXC template exists

The destructive VM lifecycle smoke test creates, updates, verifies, and deletes
the explicit disposable VMID. Cleanup refuses to delete an existing guest unless
its `mcp-lab-*` ownership marker matches the harness.

Prepare LXC templates only when explicitly opted in:

```shell
python scripts/lab_prepare_lxc_template.py --output-file release-evidence/lxc-template-plan.json
```

Storage benchmark promotion evidence uses bounded `fio` execution with
`mcp-lab-*` artifact paths, runtime and byte caps, and `--unlink=1` cleanup. Live
storage expansion remains guarded until backend-specific resize and rollback
evidence exists.

Generate sanitized lab evidence from preflight and JUnit output:

```shell
python -m pytest tests/lab -m lab --junitxml=release-evidence/lab-junit.xml
python scripts/collect_lab_evidence.py \
  --junit release-evidence/lab-junit.xml \
  --preflight release-evidence/lab-preflight.json \
  --output-file release-evidence/lab-evidence.json
```

Topology profile smoke tests are read-only unless a separate mutation/destructive
gate explicitly opts in. The current `pve-9-single-node-no-ceph` profile expects
LXC template-dependent tests to skip when no `vztmpl` content exists on the
configured storage. That skip is evidence of a prerequisite gap, not a failure.

For the full operator procedure, see `docs/lab-runbook.md`.

### SSH Sandbox Tests

SSH tests run against disposable Linux containers or lab nodes:

- Key authentication.
- Non-interactive command execution.
- Interactive session setup and teardown.
- Timeout enforcement.
- Rate limiting.
- Concurrent session limits.
- SFTP upload and download.
- SCP copy.
- Command policy allow and deny.
- Session recording references.

### Security Tests

Security tests include:

- Deny policies override allow policies.
- Approval policies block execution until valid approval.
- Expired approvals are rejected.
- Approval target mismatch is rejected.
- Secret values are redacted from logs and errors.
- SSH command policy denies unapproved arbitrary shell commands.
- Audit persistence failure blocks mutating actions.
- Tenant scope violations are rejected.

### Reliability Tests

Reliability tests simulate:

- Proxmox API transient failure.
- Proxmox task failure.
- Node unreachable.
- SSH connection failure.
- SSH command timeout.
- Redis unavailable.
- Secret backend unavailable.
- SIEM exporter unavailable.
- Alertmanager or Prometheus source unavailable.
- Network interruption.
- Quorum loss reported by Proxmox.

Expected behavior must be explicit: fail closed for security-critical dependencies, degrade for optional observability sinks, and return structured retryable errors where appropriate.

### Chaos Tests

Deterministic chaos gates run in CI with simulated dependency failures:

```shell
python -m pytest tests/chaos -q
```

Live chaos tests run only in controlled lab environments:

- Kill Proxmox node during read-only discovery.
- Restart Proxmox API while tool calls are active.
- Drop SSH connections during command execution.
- Induce Redis failover.
- Induce PostgreSQL read-only or unavailable states.
- Interrupt long-running backup or migration task.

### Performance Tests

Lightweight load gates run in CI:

```shell
python -m pytest tests/performance -q
```

Broader performance tests measure:

- Tool routing overhead.
- Policy evaluation latency.
- Audit write throughput.
- Proxmox API connection pooling.
- SSH session concurrency.
- Large inventory discovery.
- Metrics endpoint overhead.

## Test Data Strategy

Use named fixtures for:

- Tenants.
- Users.
- AI agents.
- Roles.
- Policies.
- Proxmox clusters.
- Nodes.
- VMs.
- LXC containers.
- Storage pools.
- SSH sessions.
- Approval records.
- Audit events.

Fixtures should include both homelab and enterprise multi-tenant scenarios.

## CI Test Gates

Pull requests should run:

- Formatting check.
- Lint.
- Type check.
- Unit tests.
- Contract tests.
- Migration tests.
- Kubernetes manifest validation for HTTPS health probes.
- Release workflow contract tests.
- Dependency vulnerability scan.
- Secret scan.
- Docker build.

Nightly or manual workflows should run:

- Proxmox lab integration tests.
- SSH sandbox tests.
- Chaos tests.
- Load tests.
- PostgreSQL-backed migration validation.
- Container image scanning.
- SBOM generation.

Release-candidate workflows should fail closed unless the configured evidence
directory contains valid artifacts for CI, distribution, hardening, migration
validation, SBOM, image scanning, compatibility, and lab evidence.

Compatibility evidence is tracked in `docs/proxmox-compatibility.md`. Release candidates must update that matrix when a new Proxmox version, Ceph/HA topology, backup backend, or storage backend is validated.

## Required Test Invariants

- No mutating operation executes without an audit decision event.
- No dangerous operation bypasses policy evaluation.
- No approval can be replayed for another target or input.
- No raw secret appears in captured logs.
- No SSH tool executes without SSH-specific permission.
- Dry-run mode does not mutate Proxmox state.
- Idempotent retry returns the original result or a conflict, never duplicate execution.

## Manual Acceptance Scenarios

Before a preview release, manually verify:

- Read-only discovery across a multi-node cluster.
- VM create, start, snapshot, backup, restore, and delete with approval.
- LXC create, start, snapshot, restore, and delete with approval.
- Node reboot request requires approval and records all events.
- SSH diagnostic command succeeds and records output reference.
- Arbitrary SSH command is denied unless policy allows it.
- SIEM export contains structured audit events.
- Prometheus metrics and OpenTelemetry traces correlate with audit IDs.
