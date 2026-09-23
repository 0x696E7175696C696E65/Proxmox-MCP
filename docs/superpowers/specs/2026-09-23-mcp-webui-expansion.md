# MCP + Admin WebUI expansion

Program note for the unified secure-by-design expansion (approvals UX, UPID tasks, inventory, lab promotions, agent approval status + webhook notify, observability, multi-admin dual-control).

## Security invariants

- Admin mutating APIs require session + CSRF; step-up password for decide, user management, webhook test.
- Roles: `admin` (full), `operator` (no decide/users/policy secrets), `viewer` (read-only).
- Approval tokens never appear in list/detail GET; issued once on successful decide (or second quorum approve).
- Critical risk approvals require dual-control N=2 distinct admin users.
- Approval webhook: HTTPS only, HMAC-SHA256 over `{timestamp}.{body}`.
- Domain live promotions for `verify_backup` / LVM-thin `expand_storage` are fail-closed behind settings flags until lab evidence is recorded.

## Enable flags

- `PROXMOX_MCP_APPROVAL_WEBHOOK_URL` / `PROXMOX_MCP_APPROVAL_WEBHOOK_SECRET`
- `PROXMOX_MCP_DOMAIN_PROMOTIONS_VERIFY_BACKUP_LIVE`
- `PROXMOX_MCP_DOMAIN_PROMOTIONS_EXPAND_STORAGE_LVMTHIN_LIVE`

## Migration

- `202609230001_approval_quorum_and_user_disable` adds `required_approvals`, `approval_decisions`, and `admin_users.disabled_at`.
