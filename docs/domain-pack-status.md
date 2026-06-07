# Domain Pack Status

Domain packs are promoted through the lab-first framework in `docs/tool-promotion-framework.md`.

## VM/LXC Lifecycle And Restore

Status: implemented with Proxmox API live support for lifecycle, migration, snapshot, restore, disk resize, hardware/resource, and cloud-init operations. `enter_lxc_console` now uses the durable SSH session and recording contract for live execution; it opens a recorded session reference instead of returning raw console output.

Validation:

- Unit/contract tests: `python -m pytest tests/proxmox/test_domain_vm_lxc_pack.py`
- Full domain regression: `python -m pytest tests/proxmox/test_domain_tools.py`
- Read-only lab discovery: `python -m pytest tests/lab -m lab`

Safety notes:

- Dry-run previews include endpoint, payload, impact, risk, promotion status, and rollback guidance.
- Live mutation tests must require `PROXMOX_MCP_LAB_MUTATIONS_ENABLED=true`.
- Destructive VM/LXC tests must also require `PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED=true` and disposable target IDs.

## Storage, ZFS, LVM, Volume, And Disk

Status: implemented with Proxmox API live support for storage config and volume move/copy operations, SSH live support for explicit `zpool`, `pvesm`, and `wipefs` operations, and guarded behavior for ambiguous operations that do not yet have safe universal semantics.

Live command-backed tools:

- `create_zfs_pool`: `zpool create {pool} {device}`
- `scrub_zfs_pool`: `zpool scrub {pool}`
- `create_lvm_storage`: `pvesm add lvm {storage_id} --vgname {volume}`
- `create_lvmthin_storage`: `pvesm add lvmthin {storage_id} --vgname {volume} --thinpool {pool}`
- `wipe_disk`: `wipefs -a {device}`

Still guarded:

- `expand_storage`: storage expansion is backend-specific and needs per-backend implementation.
- `benchmark_storage`: benchmark behavior must define workload, duration, target, and output contract before live execution.

Validation:

- Unit/contract tests: `python -m pytest tests/proxmox/test_domain_storage_pack.py`
- Read-only lab discovery: `python -m pytest tests/lab -m lab`

Safety notes:

- Destructive disk operations require explicit device path fields and reject traversal values.
- Live destructive lab tests must require both mutation and destructive opt-in flags.

## Network, SDN, VLAN, Bridge, Bond, And Firewall

Status: implemented with Proxmox API live support for bridge, bond, VLAN, SDN zone/VXLAN, cluster firewall rule, alias, IP set, firewall enable, and network reload/apply operations. Firewall policy test remains a read-only hybrid command-backed operation.

Validation:

- Unit/contract tests: `python -m pytest tests/proxmox/test_domain_network_firewall_pack.py`
- Read-only lab discovery: `python -m pytest tests/lab -m lab`

Safety notes:

- Network identifiers use precise schema fields (`iface`, `zone_id`, `rule_id`, `alias`, `ipset`) and reject traversal values.
- Dry-runs must be reviewed for rollback access before live bridge, bond, VLAN, SDN, or reload operations.
- Live mutation lab tests must require `PROXMOX_MCP_LAB_MUTATIONS_ENABLED=true` and console-access verification.

## Backup, Restore, Verify, Prune, And Scheduled Jobs

Status: implemented with Proxmox API live support for cluster backup jobs, VM/LXC backup requests, VM/LXC backup restore requests, and storage prune operations. Backup verification remains guarded until the exact PVE/PBS verification contract is implemented and lab-validated.

Validation:

- Unit/contract tests: `python -m pytest tests/proxmox/test_domain_backup_pack.py`
- Read-only lab discovery: `python -m pytest tests/lab -m lab`

Safety notes:

- Job mutations require explicit `job_id`.
- Backup content operations require explicit `volume` values and reject traversal values.
- Restore and prune lab tests require `PROXMOX_MCP_LAB_MUTATIONS_ENABLED=true`; destructive restore/prune tests require disposable storage and target IDs.

## Ceph And HA

Status: implemented with Proxmox API live support for Ceph pools, OSDs, MONs, HA resources, HA groups, and HA migration, plus SSH command support for Ceph OSD reweighting and rebalancing.

Validation:

- Unit/contract tests: `python -m pytest tests/proxmox/test_domain_ceph_ha_pack.py`
- Read-only lab discovery: `python -m pytest tests/lab -m lab`

Safety notes:

- Ceph mutation dry-runs must be reviewed against cluster health and quorum status before live execution.
- HA migrations require explicit `ha_resource_id` values and target payloads.
- Live Ceph/HA mutation lab tests require mutation opt-in and disposable or non-production lab resources.

## SSH, LXC Console, Diagnostics, And Support Bundle

Status: implemented with SSH command support for node diagnostics and support bundle collection. LXC console entry exposes a dry-run `pct enter {vmid}` preview and live execution opens a durable SSH session with a reserved recording reference. It does not execute `pct enter` as a one-shot command or return raw console output.

Live command-backed tools:

- `enter_lxc_console`: `pct enter {vmid}` dry-run preview, live durable session/recording reference
- `run_diagnostics`: `pvesh get /nodes/{node}/status`
- `collect_support_bundle`: `pveversion -v`

Validation:

- Unit/contract tests: `python -m pytest tests/proxmox/test_domain_ssh_console_pack.py tests/ssh`
- Read-only lab discovery: `python -m pytest tests/lab -m lab`

Safety notes:

- Interactive console usage is still bounded by SSH policy, recording, and session controls in the SSH subsystem.
- Support bundle collection avoids shell chaining by default and uses a single allowlisted command.

## Observability Runtime Wiring

Status: implemented in `ToolRegistry`. Every terminal tool execution outcome can now record metrics, emit structured JSON logs, and attach trace IDs to audit metadata when a metrics sink or log sink is configured.

Internal observability tool status:

- `get_audit_events`: live-supported when a queryable audit repository is configured; otherwise fails closed with `NOT_IMPLEMENTED`.
- `get_prometheus_metrics`: live-supported when the in-process metrics registry is configured and also exposed through `/metrics`.
- `get_recent_alerts`: remains `external_source_required` until an alert backend is configured.
- `get_resource_trends`: remains `external_source_required` until a durable metrics or time-series backend is configured.

Validation:

- Unit tests: `python -m pytest tests/tools/test_registry.py tests/observability/test_metrics.py`
- Metrics rendering: `InMemoryMetricsRegistry.render_prometheus()`

Correlation fields:

- `request_id`
- `correlation_id`
- `audit_event_id`
- `trace_id`
- `span_id`
- `tool_name`
- `connector`
- `status`

## Remaining Guarded Promotion Order

1. Promote queryable internal observability sources that can be validated without touching Proxmox state.
2. Promote `verify_backup` only after the exact PVE or PBS verification contract and lab evidence exist.
3. Promote `benchmark_storage` only with bounded workload, timeout, cleanup, and result schema guarantees.
4. Promote `expand_storage` backend-by-backend after each storage type has implementation and lab proof.
5. Promote `apply_node_updates` last because node update, reboot, rollback, and task-polling semantics have the highest operational blast radius.
