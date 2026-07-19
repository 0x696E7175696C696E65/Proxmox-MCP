# MCP Tool Specification

## Tool Contract

Every MCP tool must declare:

- `name`: stable MCP tool name.
- `description`: a non-empty, human-and-agent-readable summary of what the tool does, which target/parameters it needs, and any guarded or destructive behavior. Contract-tested for presence and specificity.
- `category`: operational domain.
- `permission`: required permission string.
- `risk`: `low`, `medium`, `high`, or `critical`.
- `dry_run`: whether the tool can preview changes.
- `approval_default`: whether approval is required by default.
- `connector`: `proxmox_api`, `ssh`, or `hybrid`.

Each tool is registered with FastMCP carrying its `description` and a per-tool input
schema of the form `{target, parameters, options}`, where `parameters` is the tool's
own parameter model (so an MCP client sees the exact keys a tool needs rather than an
opaque request envelope). `actor` is derived from the authenticated session and is not
part of the agent-facing input surface.

Mutating tools must support idempotency where Proxmox behavior allows it. Dangerous tools must support impact analysis and approval metadata.

## Cluster Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `get_cluster_status` | `cluster.status.read` | low | false | proxmox_api |
| `get_cluster_resources` | `cluster.resources.read` | low | false | proxmox_api |
| `get_cluster_config` | `cluster.config.read` | low | false | proxmox_api |
| `get_cluster_membership` | `cluster.membership.read` | low | false | proxmox_api |
| `get_cluster_quorum` | `cluster.quorum.read` | low | false | proxmox_api |
| `list_cluster_tasks` | `cluster.tasks.read` | low | false | proxmox_api |
| `get_task_status` | `cluster.tasks.read` | low | false | proxmox_api |
| `join_cluster` | `cluster.membership.write` | critical | true | proxmox_api |
| `remove_cluster_node` | `cluster.membership.delete` | critical | true | proxmox_api |
| `update_cluster_options` | `cluster.config.write` | high | true | proxmox_api |
| `get_cluster_backup_schedule` | `backup.job.read` | low | false | proxmox_api |
| `get_cluster_replication_jobs` | `cluster.replication.read` | low | false | proxmox_api |

## Node Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `list_nodes` | `node.inventory.read` | low | false | proxmox_api |
| `get_node_status` | `node.status.read` | low | false | proxmox_api |
| `get_node_version` | `node.status.read` | low | false | proxmox_api |
| `get_node_hardware` | `node.hardware.read` | low | false | hybrid |
| `get_node_services` | `node.service.read` | low | false | proxmox_api |
| `start_node_service` | `node.service.write` | medium | true | proxmox_api |
| `stop_node_service` | `node.service.write` | high | true | proxmox_api |
| `restart_node_service` | `node.service.write` | high | true | proxmox_api |
| `node_reboot` | `node.power.reboot` | critical | true | proxmox_api |
| `node_shutdown` | `node.power.shutdown` | critical | true | proxmox_api |
| `get_node_updates` | `node.package.read` | low | false | proxmox_api |
| `apply_node_updates` | `node.package.update` | high | true | hybrid |
| `get_node_journal` | `node.logs.read` | low | false | proxmox_api |
| `get_node_syslog` | `node.logs.read` | low | false | proxmox_api |
| `get_node_network_config` | `network.config.read` | low | false | proxmox_api |
| `validate_node_network_config` | `network.config.read` | low | false | proxmox_api |
| `reload_node_networking` | `network.config.apply` | critical | true | proxmox_api |
| `get_node_time` | `node.status.read` | low | false | proxmox_api |

## VM Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `list_vms` | `vm.inventory.read` | low | false | proxmox_api |
| `get_vm_status` | `vm.status.read` | low | false | proxmox_api |
| `get_vm_config` | `vm.config.read` | low | false | proxmox_api |
| `create_vm` | `vm.lifecycle.create` | high | true | proxmox_api |
| `clone_vm` | `vm.lifecycle.clone` | high | true | proxmox_api |
| `delete_vm` | `vm.lifecycle.destroy` | critical | true | proxmox_api |
| `start_vm` | `vm.lifecycle.start` | medium | true | proxmox_api |
| `stop_vm` | `vm.lifecycle.stop` | high | true | proxmox_api |
| `shutdown_vm` | `vm.lifecycle.shutdown` | medium | true | proxmox_api |
| `reboot_vm` | `vm.lifecycle.reboot` | medium | true | proxmox_api |
| `reset_vm` | `vm.lifecycle.reset` | high | true | proxmox_api |
| `suspend_vm` | `vm.lifecycle.suspend` | medium | true | proxmox_api |
| `resume_vm` | `vm.lifecycle.resume` | medium | true | proxmox_api |
| `migrate_vm` | `vm.lifecycle.migrate` | high | true | proxmox_api |
| `force_migrate_vm` | `vm.lifecycle.force_migrate` | critical | true | proxmox_api |
| `snapshot_vm` | `vm.snapshot.create` | medium | true | proxmox_api |
| `delete_vm_snapshot` | `vm.snapshot.delete` | high | true | proxmox_api |
| `rollback_vm_snapshot` | `vm.snapshot.rollback` | high | true | proxmox_api |
| `restore_vm` | `vm.backup.restore` | high | true | proxmox_api |
| `resize_vm_disk` | `vm.hardware.disk.resize` | high | true | proxmox_api |
| `update_vm_hardware` | `vm.hardware.write` | high | true | proxmox_api |
| `set_vm_cloud_init` | `vm.cloudinit.write` | medium | true | proxmox_api |
| `attach_iso_to_vm` | `vm.media.attach` | medium | true | proxmox_api |
| `detach_iso_from_vm` | `vm.media.detach` | medium | true | proxmox_api |
| `prepare_vm_install_media` | `vm.media.prepare` | high | true | proxmox_api |
| `create_vm_from_iso` | `vm.lifecycle.create` | high | true | proxmox_api |

## LXC Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `list_lxc` | `lxc.inventory.read` | low | false | proxmox_api |
| `get_lxc_status` | `lxc.status.read` | low | false | proxmox_api |
| `get_lxc_config` | `lxc.config.read` | low | false | proxmox_api |
| `create_lxc` | `lxc.lifecycle.create` | high | true | proxmox_api |
| `clone_lxc` | `lxc.lifecycle.clone` | high | true | proxmox_api |
| `delete_lxc` | `lxc.lifecycle.destroy` | critical | true | proxmox_api |
| `start_lxc` | `lxc.lifecycle.start` | medium | true | proxmox_api |
| `stop_lxc` | `lxc.lifecycle.stop` | high | true | proxmox_api |
| `shutdown_lxc` | `lxc.lifecycle.shutdown` | medium | true | proxmox_api |
| `reboot_lxc` | `lxc.lifecycle.reboot` | medium | true | proxmox_api |
| `suspend_lxc` | `lxc.lifecycle.suspend` | medium | true | proxmox_api |
| `resume_lxc` | `lxc.lifecycle.resume` | medium | true | proxmox_api |
| `snapshot_lxc` | `lxc.snapshot.create` | medium | true | proxmox_api |
| `delete_lxc_snapshot` | `lxc.snapshot.delete` | high | true | proxmox_api |
| `rollback_lxc_snapshot` | `lxc.snapshot.rollback` | high | true | proxmox_api |
| `restore_lxc` | `lxc.backup.restore` | high | true | proxmox_api |
| `update_lxc_resources` | `lxc.resources.write` | medium | true | proxmox_api |
| `enter_lxc_console` | `lxc.console.open` | high | true | hybrid |
| `list_lxc_templates` | `lxc.template.read` | low | false | proxmox_api |
| `download_lxc_template` | `lxc.template.download` | medium | true | proxmox_api |
| `delete_lxc_template` | `lxc.template.delete` | high | true | proxmox_api |
| `create_lxc_from_template` | `lxc.lifecycle.create` | high | true | proxmox_api |

## Storage Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `list_storage` | `storage.inventory.read` | low | false | proxmox_api |
| `get_storage_status` | `storage.status.read` | low | false | proxmox_api |
| `get_storage_content` | `storage.content.read` | low | false | proxmox_api |
| `list_iso_images` | `storage.iso.read` | low | false | proxmox_api |
| `download_iso_from_url` | `storage.iso.download` | medium | true | proxmox_api |
| `delete_iso_image` | `storage.iso.delete` | high | true | proxmox_api |
| `create_storage` | `storage.config.create` | high | true | proxmox_api |
| `update_storage` | `storage.config.write` | high | true | proxmox_api |
| `delete_storage` | `storage.config.delete` | critical | true | proxmox_api |
| `expand_storage` | `storage.capacity.expand` | high | true | hybrid |
| `create_zfs_pool` | `storage.zfs.create` | critical | true | hybrid |
| `get_zfs_status` | `storage.zfs.read` | low | false | hybrid |
| `scrub_zfs_pool` | `storage.zfs.scrub` | medium | true | hybrid |
| `create_lvm_storage` | `storage.lvm.create` | high | true | hybrid |
| `create_lvmthin_storage` | `storage.lvmthin.create` | high | true | hybrid |
| `create_nfs_storage` | `storage.nfs.create` | medium | true | proxmox_api |
| `create_smb_storage` | `storage.smb.create` | medium | true | proxmox_api |
| `benchmark_storage` | `storage.benchmark.run` | medium | true | ssh |
| `delete_volume` | `storage.volume.delete` | critical | true | proxmox_api |
| `move_volume` | `storage.volume.move` | high | true | proxmox_api |
| `copy_volume` | `storage.volume.copy` | medium | true | proxmox_api |
| `get_disk_inventory` | `storage.disk.read` | low | false | hybrid |
| `wipe_disk` | `storage.disk.wipe` | critical | true | hybrid |

## Networking Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `list_networks` | `network.config.read` | low | false | proxmox_api |
| `get_network_config` | `network.config.read` | low | false | proxmox_api |
| `create_bridge` | `network.bridge.create` | high | true | proxmox_api |
| `update_bridge` | `network.bridge.write` | high | true | proxmox_api |
| `delete_bridge` | `network.bridge.delete` | critical | true | proxmox_api |
| `create_bond` | `network.bond.create` | high | true | proxmox_api |
| `update_bond` | `network.bond.write` | high | true | proxmox_api |
| `delete_bond` | `network.bond.delete` | critical | true | proxmox_api |
| `create_vlan` | `network.vlan.create` | medium | true | proxmox_api |
| `update_vlan` | `network.vlan.write` | medium | true | proxmox_api |
| `delete_vlan` | `network.vlan.delete` | high | true | proxmox_api |
| `list_sdn_zones` | `network.sdn.read` | low | false | proxmox_api |
| `create_sdn_zone` | `network.sdn.create` | high | true | proxmox_api |
| `update_sdn_zone` | `network.sdn.write` | high | true | proxmox_api |
| `create_vxlan` | `network.vxlan.create` | high | true | proxmox_api |
| `apply_network_config` | `network.config.apply` | critical | true | proxmox_api |

## Firewall Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `get_firewall_rules` | `firewall.rule.read` | low | false | proxmox_api |
| `update_firewall_rules` | `firewall.rule.write` | high | true | proxmox_api |
| `create_firewall_rule` | `firewall.rule.create` | high | true | proxmox_api |
| `delete_firewall_rule` | `firewall.rule.delete` | high | true | proxmox_api |
| `enable_firewall` | `firewall.config.write` | high | true | proxmox_api |
| `disable_firewall` | `firewall.config.write` | critical | true | proxmox_api |
| `list_firewall_aliases` | `firewall.alias.read` | low | false | proxmox_api |
| `create_firewall_alias` | `firewall.alias.create` | medium | true | proxmox_api |
| `delete_firewall_alias` | `firewall.alias.delete` | medium | true | proxmox_api |
| `list_ipsets` | `firewall.ipset.read` | low | false | proxmox_api |
| `update_ipset` | `firewall.ipset.write` | medium | true | proxmox_api |
| `test_firewall_policy` | `firewall.policy.test` | low | false | hybrid |

## Backup And Restore Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `list_backup_jobs` | `backup.job.read` | low | false | proxmox_api |
| `create_backup_job` | `backup.job.create` | medium | true | proxmox_api |
| `update_backup_job` | `backup.job.write` | medium | true | proxmox_api |
| `delete_backup_job` | `backup.job.delete` | high | true | proxmox_api |
| `backup_vm` | `backup.vm.create` | medium | true | proxmox_api |
| `backup_lxc` | `backup.lxc.create` | medium | true | proxmox_api |
| `restore_vm_backup` | `backup.vm.restore` | high | true | proxmox_api |
| `restore_lxc_backup` | `backup.lxc.restore` | high | true | proxmox_api |
| `verify_backup` | `backup.verify.run` | medium | true | proxmox_api |
| `prune_backups` | `backup.retention.prune` | high | true | proxmox_api |
| `list_backup_storage` | `backup.storage.read` | low | false | proxmox_api |
| `get_backup_retention_policy` | `backup.retention.read` | low | false | proxmox_api |

## Ceph Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `get_ceph_status` | `ceph.status.read` | low | false | proxmox_api |
| `get_ceph_health` | `ceph.health.read` | low | false | proxmox_api |
| `list_ceph_pools` | `ceph.pool.read` | low | false | proxmox_api |
| `manage_ceph_pool` | `ceph.pool.write` | high | true | proxmox_api |
| `create_ceph_pool` | `ceph.pool.create` | high | true | proxmox_api |
| `delete_ceph_pool` | `ceph.pool.delete` | critical | true | proxmox_api |
| `list_ceph_osds` | `ceph.osd.read` | low | false | proxmox_api |
| `create_ceph_osd` | `ceph.osd.create` | high | true | proxmox_api |
| `remove_ceph_osd` | `ceph.osd.remove` | critical | true | proxmox_api |
| `reweight_ceph_osd` | `ceph.osd.reweight` | high | true | hybrid |
| `list_ceph_mons` | `ceph.mon.read` | low | false | proxmox_api |
| `create_ceph_mon` | `ceph.mon.create` | high | true | proxmox_api |
| `delete_ceph_mon` | `ceph.mon.delete` | critical | true | proxmox_api |
| `list_ceph_mgrs` | `ceph.mgr.read` | low | false | proxmox_api |
| `rebalance_ceph` | `ceph.rebalance.run` | high | true | hybrid |

## HA Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `list_ha_resources` | `ha.resource.read` | low | false | proxmox_api |
| `get_ha_status` | `ha.status.read` | low | false | proxmox_api |
| `create_ha_resource` | `ha.resource.create` | high | true | proxmox_api |
| `update_ha_resource` | `ha.resource.write` | high | true | proxmox_api |
| `delete_ha_resource` | `ha.resource.delete` | high | true | proxmox_api |
| `migrate_ha_resource` | `ha.resource.migrate` | high | true | proxmox_api |
| `set_ha_group` | `ha.group.write` | high | true | proxmox_api |
| `list_ha_groups` | `ha.group.read` | low | false | proxmox_api |

## Helper Script Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `sync_helper_script_catalog` | `helper.catalog.read` | low | false | hybrid |
| `search_helper_scripts` | `helper.catalog.read` | low | false | hybrid |
| `get_helper_script_details` | `helper.catalog.read` | low | false | hybrid |
| `preview_helper_script` | `helper.script.preview` | medium | true | hybrid |
| `stage_helper_script` | `helper.script.stage` | high | true | ssh |
| `execute_helper_script` | `helper.script.execute` | critical | true | ssh |
| `get_helper_script_execution` | `helper.script.execution.read` | low | false | internal |
| `cancel_helper_script_execution` | `helper.script.execution.cancel` | high | true | internal |
| `run_helper_app_install` | `helper.script.execute` | critical | true | ssh |

## User And Permission Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `list_users` | `user.read` | low | false | proxmox_api |
| `create_user` | `user.create` | high | true | proxmox_api |
| `update_user` | `user.write` | high | true | proxmox_api |
| `delete_user` | `user.delete` | critical | true | proxmox_api |
| `list_groups` | `group.read` | low | false | proxmox_api |
| `create_group` | `group.create` | medium | true | proxmox_api |
| `delete_group` | `group.delete` | high | true | proxmox_api |
| `list_roles` | `role.read` | low | false | proxmox_api |
| `create_role` | `role.create` | high | true | proxmox_api |
| `delete_role` | `role.delete` | high | true | proxmox_api |
| `list_permissions` | `permission.read` | low | false | proxmox_api |
| `update_permissions` | `permission.write` | critical | true | proxmox_api |

## Monitoring Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `get_cluster_health` | `monitoring.health.read` | low | false | hybrid |
| `get_cpu_metrics` | `monitoring.cpu.read` | low | false | proxmox_api |
| `get_ram_metrics` | `monitoring.ram.read` | low | false | proxmox_api |
| `get_disk_metrics` | `monitoring.disk.read` | low | false | hybrid |
| `get_network_metrics` | `monitoring.network.read` | low | false | proxmox_api |
| `get_zfs_health` | `monitoring.zfs.read` | low | false | ssh |
| `get_smart_data` | `monitoring.smart.read` | low | false | ssh |
| `get_ceph_metrics` | `monitoring.ceph.read` | low | false | proxmox_api |
| `get_prometheus_metrics` | `monitoring.metrics.read` | low | false | internal |
| `get_recent_alerts` | `monitoring.alerts.read` | low | false | internal |
| `get_resource_trends` | `monitoring.trends.read` | low | false | internal |
| `run_diagnostics` | `monitoring.diagnostics.run` | medium | true | hybrid |
| `collect_support_bundle` | `monitoring.support.collect` | high | true | hybrid |
| `get_audit_events` | `audit.event.read` | low | false | internal |

## SSH Tools

| Tool | Permission | Risk | Dry Run | Connector |
| --- | --- | --- | --- | --- |
| `execute_ssh` | `ssh.command.execute` | critical | true | ssh |
| `execute_ssh_interactive` | `ssh.session.interactive` | critical | false | ssh |
| `open_ssh_session` | `ssh.session.open` | high | false | ssh |
| `close_ssh_session` | `ssh.session.close` | medium | false | ssh |
| `upload_file` | `ssh.file.upload` | high | true | ssh |
| `download_file` | `ssh.file.download` | medium | false | ssh |
| `sftp_list` | `ssh.sftp.list` | low | false | ssh |
| `sftp_mkdir` | `ssh.sftp.mkdir` | medium | true | ssh |
| `sftp_delete` | `ssh.sftp.delete` | critical | true | ssh |
| `scp_copy` | `ssh.scp.copy` | high | true | ssh |

## Tool Count

This catalog defines more than 170 initial tools. Implementation should ship them in staged groups rather than exposing unimplemented placeholders. Each shipped tool must include schema validation, permission metadata, audit coverage, tests, and documentation.
