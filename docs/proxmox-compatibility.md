# Proxmox Compatibility Matrix

This matrix records evidence, not marketing claims. A Proxmox version or topology is supported only when the listed tests and lab notes exist for that row.

## Version Evidence

| Proxmox VE version | Topology | Evidence date | Evidence | Status |
| --- | --- | --- | --- | --- |
| Proxmox VE 9.1.1 | Single node, node `test`, storage `local` and `local-lvm`, no Ceph, no existing guests | 2026-06-06 | Read-only lab smoke tests: `4 passed, 1 skipped`; disposable VM mutation smoke: `1 passed`; Ceph skipped because it was not installed | Preview lab evidence |
| Offline release gates | No live Proxmox dependency | 2026-06-06 | Chaos and lightweight load gates: `5 passed`; lab gates skipped safely because `PROXMOX_MCP_LAB_ENABLED=true` was not configured in this shell | Release gate evidence |
| Proxmox VE 8.x multi-node | Pending | Pending | Needs read-only discovery, HA, migration, backup, and SSH evidence | Not yet claimed |
| Proxmox VE 9.x multi-node | Pending | Pending | Needs API compatibility review, multi-node discovery, migration, HA, backup, and SSH evidence | Not yet claimed |

## Topology-Specific Claims

- Ceph tools require a lab with Ceph installed before Ceph operations are advertised as validated.
- HA tools require HA resources and groups in the lab before HA migration or failover behavior is advertised as validated.
- Backup verification requires an exact PVE or PBS verification contract before `verify_backup` can be promoted.
- Storage expansion is backend-specific; ZFS, LVM, LVM-thin, directory, NFS/SMB, and Ceph must be promoted independently.
- Node update orchestration remains guarded until update, reboot, task polling, and rollback behavior are proven in a disposable lab.
- Username/password ticket-auth labs should use realm-qualified usernames such as `root@pam`; plain usernames may fail authentication on Proxmox.

## Lab Profiles

| Profile | Required evidence | Expected skips | Promotion eligibility |
| --- | --- | --- | --- |
| `pve-9-single-node-no-ceph` | Read-only discovery, registered read tool execution, disposable VM create/update/delete, backup create/list, `local` storage discovery | Ceph, HA, PBS, multi-node, LXC lifecycle when no template exists | Preview only |
| `pve-9-storage-local-local-lvm` | `local` directory storage content reads and `local-lvm` LVM-thin metadata/status reads | Storage expansion and benchmarking | Storage discovery preview |
| `pve-9-single-node-with-guests` | Existing guest inventory plus safe read-only VM/LXC config/status reads | HA, migration, PBS unless configured | Read-only guest management preview |
| `pve-9-ceph-enabled` | `tests/lab/test_ceph_profile_smoke.py` reads node Ceph status | Ceph mutations until separately proven | Ceph read-only preview |
| `pve-9-ha-enabled` | `tests/lab/test_ha_profile_smoke.py` reads HA cluster status/resources | HA migration/failover until disposable tests exist | HA read-only preview |
| `pve-9-multi-node` | `tests/lab/test_multi_node_profile_smoke.py` validates node count and cluster status | Destructive migration unless isolated | Multi-node preview |
| `pve-9-pbs-enabled` | `tests/lab/test_pbs_profile_smoke.py` validates a configured PBS storage backend; `tests/lab/test_backup_verify_smoke.py` records verification prerequisites | Live backup verification before artifact evidence | Backup verification candidate |

Profiles not listed as preview or qualified are `Not yet claimed`. A profile can
move from preview to qualified only when required tests pass without required
skips and the structured evidence artifacts include the exact profile name.

Profile-specific environment variables:

- `pve-9-multi-node` requires `PROXMOX_MCP_LAB_EXPECTED_NODE_COUNT=2` or higher.
- `pve-9-pbs-enabled` requires `PROXMOX_MCP_LAB_PBS_REPOSITORY=<storage-id>`.
- LXC lifecycle promotion can use `PROXMOX_MCP_LAB_LXC_TEMPLATE_STORAGE` and `PROXMOX_MCP_LAB_LXC_TEMPLATE_VOLID` when template discovery should not rely on the default storage.

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
