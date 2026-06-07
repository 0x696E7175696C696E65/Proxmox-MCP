# Release Candidate Notes

This project remains an actively developed public preview until release evidence
contains complete profile-specific qualification artifacts. These notes separate
implemented capability from promotion claims so reviewers can audit the release
without relying on marketing language.

## Required Evidence Artifacts

- `artifact-manifest.json` with SHA-256 hashes for every required evidence file.
- `ci-success.json`, `distribution-summary.json`, `hardening-summary.json`, and `migration-validation.json`.
- `sbom.spdx.json` and `trivy-image-results.sarif`.
- `compatibility-report.json` and `lab-evidence.json` with no credential-shaped keys.

## Preview Capabilities

- Registered MCP execution path with auth session injection, RBAC, policy, approvals, auditing, and risk metadata.
- Proxmox read, VM/LXC mutation, backup create/list, storage discovery, SSH session, and console contracts that have passing unit and preview lab tests.
- HTTPS-only configuration validation for MCP transport, Proxmox API, PostgreSQL, Redis, and external observability/secret endpoints.

## Profile-Gated Capabilities

- `pve-9-single-node-no-ceph` has preview lab evidence for read-only, registered MCP read, disposable VM mutation, backup create/list, and storage profile smoke tests.
- `pve-9-storage-local-local-lvm`, `pve-9-ceph-enabled`, `pve-9-ha-enabled`, `pve-9-multi-node`, and `pve-9-pbs-enabled` require their named lab profiles and required tests before support claims can move beyond preview.

## Operator-Qualified Deployment Gates

- Production mode must configure external auth, durable state, PostgreSQL TLS, Redis TLS, TLS certificate material, and an enterprise secret provider.
- Workload identity production deployments must use a Redis-backed replay cache.
- Alertmanager, Prometheus, SIEM, and vendor secret providers are configured by operators and must use HTTPS or provider-native secure channels.

## Still-Guarded Capabilities

- `verify_backup` remains guarded until PBS or PVE-local verification has backend-specific artifact verification and restore-preview evidence.
- `expand_storage` remains guarded for live execution until each backend has disposable lab proof.
- `benchmark_storage` remains guarded for live execution until bounded workload and cleanup evidence exist.
- `apply_node_updates` remains guarded until update preflight, rollback, reboot/reconnect, and failure recovery evidence exist.
