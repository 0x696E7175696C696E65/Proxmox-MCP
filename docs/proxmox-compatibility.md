# Proxmox Compatibility Matrix

This matrix records evidence, not marketing claims. A Proxmox version or topology is supported only when the listed tests and lab notes exist for that row.

## Version Evidence

| Proxmox VE version | Topology | Evidence date | Evidence | Status |
| --- | --- | --- | --- | --- |
| Fresh Proxmox VE lab, single node | No production data, node `test`, no Ceph | 2026-06-06 | Read-only lab smoke tests: `5 passed, 1 skipped`; Ceph skipped because it was not installed | Preview lab evidence |
| Offline release gates | No live Proxmox dependency | 2026-06-06 | Chaos and lightweight load gates: `5 passed`; lab gates skipped safely because `PROXMOX_MCP_LAB_ENABLED=true` was not configured in this shell | Release gate evidence |
| Proxmox VE 8.x multi-node | Pending | Pending | Needs read-only discovery, HA, migration, backup, and SSH evidence | Not yet claimed |
| Proxmox VE 9.x | Pending | Pending | Needs API compatibility review and lab evidence | Not yet claimed |

## Topology-Specific Claims

- Ceph tools require a lab with Ceph installed before Ceph operations are advertised as validated.
- HA tools require HA resources and groups in the lab before HA migration or failover behavior is advertised as validated.
- Backup verification requires an exact PVE or PBS verification contract before `verify_backup` can be promoted.
- Storage expansion is backend-specific; ZFS, LVM, LVM-thin, directory, NFS/SMB, and Ceph must be promoted independently.
- Node update orchestration remains guarded until update, reboot, task polling, and rollback behavior are proven in a disposable lab.

## Release Evidence Gates

Every preview or GA candidate should attach or update:

- CI, distribution, and hardening workflow results.
- Migration validation output from `tests/release/test_migration_gate.py`.
- SBOM artifact and container image scan artifact.
- Chaos gate results from `tests/chaos/`.
- Lightweight load gate results from `tests/performance/`.
- Lab promotion evidence for every newly promoted live tool.

The release-candidate validator expects structured `compatibility-report.json`
and `lab-evidence.json` artifacts. Examples live in
`docs/release-evidence/compatibility-report.example.json` and
`docs/release-evidence/lab-evidence.example.json`. These artifacts must contain
evidence summaries only; do not include usernames, passwords, service tokens,
private keys, or raw credential references.

## Current Known Limits

- Multi-replica SSH sessions require the database-backed session store and recording store to be configured; in-memory development sessions are not a production HA mode.
- Alert and trend tools require configured HTTPS Alertmanager and Prometheus-compatible backends before returning source data.
- SIEM retry delivery has a durable queue, but vendor-specific delivery adapters and worker deployment are operator-specific.
