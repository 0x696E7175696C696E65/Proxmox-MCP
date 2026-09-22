# Runtime & Approvals pipelines (logic + WebUI)

**Date:** 2026-09-22  
**Status:** Approved for implementation planning  
**Repo:** `proxmox-mcp-main` (MCP + Admin WebUI)

## Problem

1. **Approvals E2E is broken.** When a dangerous MCP tool requires approval, the guard returns `APPROVAL_REQUIRED` but never creates a pending row. The Approvals WebUI queue stays empty. Even if a row is decided, agents never receive a one-time `approval_token` to retry, so `consume()` cannot close the loop.

2. **Policy hot-apply is a lie.** `PUT /admin/api/policy` (and config) updates `ConfigStore` / env, but the live MCP `SecurityPlaneGuard` still reads **startup** `Settings.dangerous_operations` until process restart.

3. **AuthZ hole.** Operators cannot call `PUT /admin/api/policy`, but they **can** change `dangerous_operations_*` (and cluster fields) via `PUT /admin/api/config`.

4. **Runtime UX / integrity gaps.** Restart has no step-up, no reconnect overlay (unlike host switch), and `request_restart()` clears `restart_required` *before* the process actually exits/recycles. Proxmox token rotation often does not set `restart_required` even though the Proxmox client is process-bound.

## Goal

Ship a **secure-by-design, through-and-through** Approvals + Runtime pipeline:

- Dangerous op → pending queue → admin step-up decide → one-time token → agent retry → consume once.
- Policy and dangerous-ops settings affect live MCP immediately **or** clearly require restart (no silent stale Settings).
- Restart is admin + step-up, with the same phased reconnect UX as host switch.
- Operators cannot weaken policy or retarget the cluster via Config.

## Non-goals

- Holding in-flight tool executions server-side until approve (auto-resume / approach C).
- Push/webhook notification to external agents (optional later; agent polls or operator pastes token).
- Exposing plaintext approval tokens in list/detail APIs for browsers.
- Replacing Docker/supervisor restart with in-process hot reload of the Proxmox HTTP client (may still need restart for credential materialization).
- Multi-approver workflows / quorum.

## Current baseline (reuse)

| Piece | Location | Role |
|--------|----------|------|
| Guard consume path | `security/__init__.py` | Validates token; never mints |
| Approval store | `approvals/__init__.py` | `add`, `list_approvals`, `decide`, `consume` |
| Admin decide/policy | `admin/control.py` | HTTP for queue + policy |
| Restart | `admin/app.py` `post_restart`, `config_store.RuntimeController` | Deferred `os._exit` |
| Step-up pattern | secrets PUT/reveal in `admin/app.py` | Password re-check |
| Reconnect overlay | `web/.../host-restart-overlay.tsx`, `wait-for-admin.ts` | Host switch UX |
| Approvals / Runtime UI | `ApprovalsPage.tsx`, `RuntimePage.tsx` | Incomplete E2E |

## Design

### 1. Mint pending approvals (MCP path)

When `SecurityPlaneGuard` (or registry) decides **approval required** and `request.options.approval_token` is absent:

1. Build binding hashes (existing helpers): `operation` / permission, `target_hash`, `input_hash`, actor ids, risk.
2. Generate `approval_request_id` (UUID).
3. Persist via `approval_store.add(...)` with:
   - `status=pending`
   - `approval_token_hash` = hash of a random **non-consumable placeholder** (or nullable until approve — prefer placeholder so column stays NOT NULL)
   - expiry (default **30 minutes**; overridable later via settings)
   - optional **redacted summary** for UI (tool name, target resource refs, risk) — never raw secrets
4. Do **not** return any approval token to the caller.
5. Return `ToolGuardDecision.requires_approval` / tool error with:
   - `error_code=APPROVAL_REQUIRED`
   - `approval_request_id`
   - `expires_at`
   - human message instructing retry after admin approval (with token from admin)

Idempotency: if the same actor+operation+target_hash+input_hash already has a **pending** unexpired row, return that `approval_request_id` instead of creating a duplicate (lookup-before-insert).

Audit: write tool finished / `approval.queued` with `approval_request_id` in metadata (never token).

`consume()` must reject tokens while status is `pending` (only `approved` + matching hash + unconsumed).

### 2. Decide + one-time token release

`POST /admin/api/approvals/{id}/decide`:

| Requirement | Rule |
|-------------|------|
| AuthN | Admin session + CSRF |
| AuthZ | **Admin role only** (move decide into admin-only set; operators read queue only) |
| Step-up | Body must include `password`; verify like secrets |
| Body | `decision: approved \| rejected`, optional `reason`, `password` |

On **rejected**: set status `rejected`; audit; no token.

On **approved**:

1. Transition `pending → approved` under `SELECT … FOR UPDATE` (already present).
2. Persist `decided_by`, `reason`, `decided_at` (schema/migration if columns missing).
3. Return **once** in the JSON response:
   ```json
   { "approval": { ... }, "approval_token": "<T>" }
   ```
   **Token strategy (A2, chosen):** On approve, generate high-entropy `T`, set `approval_token_hash=hash(T)`, return `T` once. Pending rows are never consumable. Do not encrypt tokens at rest.

Agent retry: same tool call with `options.approval_token=T`. `consume` requires status `approved`, matching hashes, unexpired, not previously consumed.

Never include `approval_token` in `GET /admin/api/approvals` or list payloads.

### 3. Live policy / settings propagation

Shared mutable settings holder used by:

- Admin `ConfigStore` after `apply_config` / `apply_secrets`
- MCP `context_factory` / guard (read **current** `dangerous_operations` each evaluate)

Concrete pattern:

- Introduce `SettingsProvider` / `AppState.settings` object that `config_store` updates in-process and MCP reads via closure on that holder (not a frozen copy from `build_server`).
- When a field **cannot** be hot-applied (e.g. Proxmox client rebuild needs restart), set `restart_required=True` with an explicit message and surface it in Runtime UI.

Policy PUT and Config dangerous-ops fields must update the live holder so require_approval toggles take effect without restart.

### 4. AuthZ hardening

| Action | Allowed |
|--------|---------|
| List approvals | admin + operator (read) |
| Decide approval | **admin** + step-up |
| PUT policy | **admin** + step-up |
| PUT config fields `dangerous_operations_*` | **admin** only (reject 403 for operator) |
| PUT config cluster / credential path / default actor | **admin** only |
| Other benign config (log_level) | admin; operator optional (prefer admin-only for v1 consistency) |
| Runtime restart | **admin** + step-up |

WebUI: hide or disable policy/dangerous/cluster controls for operators; Approvals page read-only actions for operators.

### 5. Runtime pipeline

**API `POST /admin/api/runtime/restart`:**

- Admin + CSRF + **step-up password**
- Audit before scheduling exit
- Do **not** clear `restart_required` until next successful boot (`mark_restarted` on startup after healthy bind), or clear only after exit is irreversible and document that banner may reappear if supervisor fails
- Prefer: `request_restart` sets `restart_requested=true` but leaves `restart_required` until process death; on boot, `mark_restarted()` / clear flags

**Also set `restart_required` when:**

- Service token changes (already)
- Proxmox API token material changes that require client rebuild
- Any apply that cannot update live Proxmox client

**WebUI RuntimePage:**

- Reuse `HostRestartOverlay` phases (or shared `ProcessRestartOverlay`) after successful restart POST (treat network drop as expected)
- Step-up password modal before restart (same pattern as Secrets)
- Show clear reason string for `restart_required`
- Poll `waitForAdminReady` then refresh status

### 6. Approvals WebUI

- Pending queue with detail drawer: operation, actor, risk, expiry, redacted summary, status
- Approve / Deny → step-up modal (+ optional reason)
- On approve success: show one-time token panel with copy + warning (“shown once”)
- Tabs or filter: pending / recent decided
- Policy card: admin-only, step-up on apply, copy that live Settings update is immediate
- Faster refresh while pending count > 0; optional SSE later
- Empty state explaining mint path (accurate after this work)

### 7. Expiry

Background or on-list lazy transition: `pending` past `expires_at` → `expired`. Consume rejects expired. Optional periodic sweeper in runtime startup task.

## Security properties (explicit)

- No plaintext tokens in list APIs or audit metadata
- Approve/deny/restart/policy require session + CSRF + admin + step-up
- Token single-use (`consume` + consumed_at)
- Binding hashes prevent token replay on different target/input
- Operators cannot disable approval gates via Config bypass
- Fail closed if approval store unavailable (503 on decide; tools deny / require approval without silent allow)

## Testing

| Case | Expect |
|------|--------|
| Dangerous tool, no token | Pending row created; response has `approval_request_id`; list shows it |
| Operator decide | 403 |
| Admin decide without password | 401/403 step-up fail |
| Approve → token once → consume success | Tool allowed; second consume fails |
| Reject → retry with any token | Denied |
| Expired pending | Not consumable; status expired |
| Operator PUT config dangerous_ops | 403 |
| Policy toggle | Live guard behavior changes without restart |
| Restart with step-up | Overlay reconnect; process recycles |
| CSRF missing on decide/restart | 403 |

## Files likely touched

- `src/proxmox_mcp/security/__init__.py`
- `src/proxmox_mcp/approvals/__init__.py`
- `src/proxmox_mcp/tools/registry.py` (error payload)
- `src/proxmox_mcp/admin/control.py`, `app.py`, `config_store.py`
- `src/proxmox_mcp/server/app.py`, `runtime.py`
- `src/proxmox_mcp/persistence/models/approval.py` + migration
- `web/src/pages/ApprovalsPage.tsx`, `RuntimePage.tsx`, `ConfigPage.tsx`, `api.ts`
- Shared step-up modal + restart overlay reuse
- Tests under `tests/admin/`, `tests/security/`, `tests/approvals/`

## Implementation order

1. AuthZ gates on config/policy + live Settings holder  
2. Approval mint (A2) + decide token return + migration fields  
3. Approvals WebUI (detail, step-up, one-time token)  
4. Runtime step-up + overlay + restart_required semantics  
5. Tests + docs alignment  

## Open points (resolved defaults for planning)

| Topic | Decision |
|-------|----------|
| Pending TTL | **30 minutes** default |
| Operator Approvals access | **Read-only** (list/detail; no decide/policy) |
| Operator config | **Admin-only** for log_level + cluster + dangerous-ops in this increment |
