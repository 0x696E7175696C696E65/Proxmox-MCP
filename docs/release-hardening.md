# Release Hardening Runbook

## Preview Release Gates

Before tagging a preview release, run:

1. Formatting, linting, type checking, and unit tests.
2. Tool catalog contract tests against `docs/tool-specification.md`.
3. Alembic migration upgrade tests against a disposable PostgreSQL database.
4. Security invariant regression suite for auth, RBAC, policy, approvals, audit evidence, redaction, and transport enforcement.
5. Docker image build.
6. Dependency vulnerability audit and SBOM generation.
7. Lab-only SSH, chaos, and performance gates when Proxmox lab credentials are configured.

Current lab-rollout evidence:

- `python -m ruff format .`: clean
- `python -m ruff check .`: clean
- `python -m pyright`: `0 errors, 0 warnings`
- Security invariant suite: `54 passed`
- `python -m pytest`: `230 passed, 6 skipped`
- Lab skips were expected because `PROXMOX_MCP_LAB_ENABLED=true` was not configured in the local environment.
- Domain-pack contract tests cover VM/LXC, storage/ZFS/LVM/disk, network/firewall, backup, Ceph/HA, SSH/console, and observability runtime wiring.

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

- SSH interactive sessions should remain sticky to a single replica until a session broker is introduced.
- Lab chaos gates require operator-provided Proxmox credentials and are not enabled by default.
- SIEM exporters format payloads locally; production delivery retries should be backed by a durable queue.
- Backend-specific operations without universal safe semantics remain guarded with `NOT_IMPLEMENTED` until lab evidence exists.
