# Release Hardening Runbook

## Preview Release Gates

Before tagging a preview release, run:

1. Formatting, linting, type checking, and unit tests.
2. Tool catalog contract tests against `docs/tool-specification.md`.
3. Alembic migration upgrade tests against disposable SQLite and PostgreSQL databases plus model/schema parity checks.
4. Security invariant regression suite for auth, RBAC, policy, approvals, audit evidence, redaction, and transport enforcement.
5. Kubernetes manifest validation for HTTPS health probes and release workflow contracts.
6. Secret scanning, dependency vulnerability audit, Docker image build, Trivy image scan, and SBOM generation.
7. Release-candidate evidence validation for CI, distribution, hardening, migration, SBOM, image scan, compatibility, and lab evidence artifacts.
8. Lab-only SSH, chaos, and performance gates when Proxmox lab credentials are configured.

Current lab-rollout evidence:

- `python -m ruff format .`: clean
- `python -m ruff check .`: clean
- `python -m pyright`: `0 errors, 0 warnings`
- Security invariant suite: `54 passed`
- `python -m pytest`: `249 passed, 6 skipped` before Phase 1 wiring; rerun full verification after each gate change.
- Lab skips were expected because `PROXMOX_MCP_LAB_ENABLED=true` was not configured in the local environment.
- Domain-pack contract tests cover VM/LXC, storage/ZFS/LVM/disk, network/firewall, backup, Ceph/HA, SSH/console, and observability runtime wiring.
- Release hardening gates now include `tests/release/test_migration_gate.py`, `tests/deploy/test_kubernetes_manifest.py`, `tests/release/test_workflow_contracts.py`, `tests/chaos/`, and `tests/performance/`.
- Compatibility evidence is tracked in `docs/proxmox-compatibility.md` and must be updated before tagging a release candidate.

## Remaining Release Qualification Matrix

| Area | Current readiness | Required tests | Release gate |
| --- | --- | --- | --- |
| Documentation truthfulness | Preview status reconciled across README, roadmap, domain-pack status, and this runbook | Documentation review and CI markdown checks | Release checklist confirms no production-ready claims without evidence |
| Migrations | Alembic migration exists for audit, approval, and idempotency records | SQLite and PostgreSQL upgrade validation plus model/schema parity checks | `hardening.yml` runs SQLite and PostgreSQL migration gates |
| Container supply chain | Docker image builds in distribution workflow | Image vulnerability scan and SBOM artifact upload | `hardening.yml` uploads Trivy SARIF and SBOM artifacts |
| Runtime readiness | Dependency-aware live/ready payloads and HTTPS runtime exist | Manifest tests assert HTTPS `/health/live`, `/health/ready`, and startup probes | Kubernetes probes use HTTPS endpoints and do not fall back to raw TCP |
| Shared-state HA | Database-backed approval, idempotency, SSH session, SSH recording, and Proxmox task stores exist | Multi-replica approval consumption, idempotency locking, audit persistence, SSH session/recording behavior, and task-state replay | HA test suite documents replica-safe paths and requires durable stores for multi-replica claims |
| External observability | In-process metrics/log/trace wiring exists; Alertmanager and Prometheus adapters are available when configured | Query tests for audit events, Alertmanager alert normalization, Prometheus trend normalization, required-source readiness, and explicit external-source responses when unconfigured | Internal tools must return real source data or `external_source_required` |
| SIEM delivery | SIEM payload formatting plus durable retry/dead-letter queue exists | Queue redaction, retry, dead-letter, and audit-writer degradation tests | Audit DB remains authoritative; SIEM delivery degrades for read-only operations and retries durably |
| Guarded Proxmox tools | Guarded tools fail visibly instead of returning fake success | Contract, unit, and opt-in lab tests per promoted tool | Tool promotion checklist and evidence must be attached |
| Compatibility | Disposable lab evidence exists for the current lab only | Version/topology matrix for tested Proxmox and optional Ceph/HA/PBS features | Release notes include compatibility report |
| Release evidence | Evidence requirements are explicit | Release-candidate workflow fails when required evidence artifacts are missing or invalid | `.github/workflows/release-candidate.yml` runs `scripts/validate_release_evidence.py` |
| Chaos and load | Deterministic non-lab chaos/load gates exist; live lab gates remain opt-in | `tests/chaos/`, `tests/performance/`, and lab gates when credentials are configured | Hardening workflow runs executable pytest gates and fails closed when lab gates are enabled without required lab config |

## Chaos Scenarios

Run these only against an isolated lab cluster:

- Restart the Proxmox API while read-only discovery runs.
- Drop SSH connections during command execution.
- Simulate PostgreSQL unavailability during mutating tool execution.
- Simulate Redis failover during approval and idempotency workflows.
- Interrupt a long-running backup or migration task and confirm structured retryable errors.

Security-critical dependencies must fail closed. Optional observability exporters may degrade without blocking read-only operations.

## Rollback

1. Stop new mutating requests at the gateway or policy layer.
2. Drain application replicas.
3. Roll back the application image.
4. Verify database migrations are forward-compatible before attempting application rollback.
5. Confirm audit continuity and approval replay protection.
6. Re-enable mutating tools after a successful smoke test.

## Known Limitations

- SSH interactive sessions should use the database-backed session store for multi-replica deployments; in-memory development sessions still require sticky routing.
- Lab chaos gates require operator-provided Proxmox credentials and are not enabled by default.
- SIEM exporters format payloads locally and can use the durable retry queue; vendor-specific delivery adapters beyond the current generic delivery protocol still require deployment-specific wiring.
- Release-candidate validation requires evidence artifacts to be staged under the configured evidence directory.
- Backend-specific operations without universal safe semantics remain guarded with `NOT_IMPLEMENTED` until lab evidence exists.
