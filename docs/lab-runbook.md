# Disposable Proxmox Lab Runbook

This runbook is for disposable Proxmox VE servers only. Do not run these gates
against a production cluster or a host containing data you need to keep.

## 1. Configure Session-Only Environment

Set lab credentials in the shell session or an ignored local env file. Never
commit usernames, passwords, tickets, cookies, API tokens, private keys, or
certificate material.

Required read-only variables:

- `PROXMOX_MCP_LAB_ENABLED=true`
- `PROXMOX_MCP_LAB_API_ENDPOINT=https://pve.example.test:8006`
- `PROXMOX_MCP_LAB_USERNAME=user@realm` and `PROXMOX_MCP_LAB_PASSWORD=...`, or
  `PROXMOX_MCP_LAB_TOKEN_ID=user@realm!token` and `PROXMOX_MCP_LAB_TOKEN_SECRET=...`
- `PROXMOX_MCP_LAB_NODE=<node-name>`
- `PROXMOX_MCP_LAB_STORAGE=<storage-id>`
- `PROXMOX_MCP_LAB_PROFILE=pve-9-single-node-no-ceph`

If the disposable server uses self-signed TLS, keep `https://` and set both:

- `PROXMOX_MCP_LAB_TLS_VERIFY=false`
- `PROXMOX_MCP_LAB_ALLOW_INSECURE_TRANSPORT=true`

## 2. Run Preflight First

Run preflight before any mutation:

```shell
python scripts/lab_preflight.py --output-file release-evidence/lab-preflight.json
```

The preflight checks HTTPS endpoint shape, node discovery, storage discovery,
profile prerequisites, TLS verification mode, and sanitized metadata. The output
must not contain credential-shaped keys.

## 3. Choose Disposable IDs

Pick VMID and CTID values that do not already exist:

- `PROXMOX_MCP_LAB_TEST_VMID=<explicit disposable VMID>`
- `PROXMOX_MCP_LAB_TEST_CTID=<explicit disposable CTID>`

The harness creates resources with `mcp-lab-*` names and refuses to delete a VM
or CT unless the ownership marker matches the explicit ID.

## 4. Run Read-Only Tests

Start with read-only lab tests:

```shell
python -m pytest tests/lab -m lab --junitxml=release-evidence/lab-junit.xml
```

Missing credentials, missing profile prerequisites, or missing templates should
skip with actionable reasons rather than failing or leaking secrets.

## 5. Enable Mutations Deliberately

Only after read-only preflight passes, enable destructive gates:

- `PROXMOX_MCP_LAB_MUTATIONS_ENABLED=true`
- `PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED=true`

Then run targeted tests for VM lifecycle, LXC lifecycle, backup artifact
creation, storage evidence, and node update preflight. Live node updates remain
guarded.

## 6. LXC Template Preparation

If no LXC template exists, use the planner first:

```shell
python scripts/lab_prepare_lxc_template.py --output-file release-evidence/lxc-template-plan.json
```

Template bootstrap requires both:

- `PROXMOX_MCP_LAB_LXC_TEMPLATE_BOOTSTRAP_ENABLED=true`
- `PROXMOX_MCP_LAB_HELPER_SCRIPTS_ENABLED=true`

The bootstrap path uses the Proxmox API and records the equivalent allowlisted
`pveam update` / `pveam download` commands. It does not use `curl | bash` or
unpinned helper scripts.

## 7. ISO, Media, And Helper Script Gates

Media and helper-script expansion should be validated in this order:

1. List ISO images and LXC templates on disposable storage.
2. Download an ISO only from an `https://` URL without userinfo.
3. Attach and detach ISO media on a disposable VM.
4. Download one LXC template through the Proxmox API.
5. Sync the helper-script catalog from `community-scripts/ProxmoxVE`; simulate
   primary failure to confirm fallback to the project owner's fork.
6. Preview and stage a helper script, confirming SHA-256 and staged path evidence.
7. Execute only a selected low-risk helper script after explicit approval and
   SSH policy configuration for the helper runner.

Do not run helper scripts through generic `execute_ssh`. Helper-script execution
must use `execute_helper_script` or `run_helper_app_install` so source repo,
commit, hash, fallback usage, approval, and target metadata are audited.

## 8. Collect Evidence

Generate sanitized lab evidence from preflight and JUnit output:

```shell
python scripts/collect_lab_evidence.py \
  --junit release-evidence/lab-junit.xml \
  --preflight release-evidence/lab-preflight.json \
  --output-file release-evidence/lab-evidence.json
```

Then assemble release evidence:

```shell
python scripts/collect_release_evidence.py \
  --source-dir release-evidence \
  --output-dir release-evidence

python scripts/validate_release_evidence.py release-evidence
```

## 9. Promotion Rules

- `verify_backup` remains guarded until a backend has actual PVE-local or PBS
  verification proof.
- `restore_vm_backup` dry-run can record read-only artifact and target-conflict
  preconditions; live restore still requires explicit mutation gates.
- `benchmark_storage` supports bounded `fio` execution only with `mcp-lab-*`
  artifact paths, runtime/size caps, and `--unlink=1` cleanup evidence.
- `expand_storage` remains guarded per backend until resize, rollback, and
  cleanup proof exists.
- `apply_node_updates` remains guarded until update, reboot, reconnect,
  rollback, and failure recovery are proven.
- Helper-script execution remains profile-gated until the exact script category
  has source pinning, SHA-256, approval, SSH policy, and disposable lab evidence.

## 10. Cleanup

Rerun the targeted smoke tests after interruption; shared resource helpers clean
up matching `mcp-lab-*` VM/LXC resources. If manual cleanup is required, confirm
the VM/CT name or hostname starts with the exact expected ownership marker before
deleting it.
