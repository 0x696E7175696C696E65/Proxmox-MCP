# Multi-host Proxmox switch (WebUI → MCP restart)

**Date:** 2026-09-22  
**Status:** Approved for implementation planning  
**Repo:** `proxmox-mcp-main` (MCP + Admin WebUI)

## Problem

The operator has **two independent Proxmox hosts** (not one corosync cluster). Today the MCP process binds to **exactly one** API endpoint (`Settings.cluster`). Managing the other host requires editing env/secrets and recycling the container by hand.

## Goal

Add a **server catalog + WebUI switcher**: choosing a host writes that host as the active Proxmox endpoint/credentials and **restarts the MCP process** so all tools and the Admin UI talk to the selected server only.

## Non-goals

- In-process multi-client pool or simultaneous connections to both hosts
- Fan-out inventory (`list_vms` across both hosts in one call)
- Per-tool `target.cluster` routing to a non-active host
- Cross-host migrate / copy / shared storage assumptions
- Treating the two hosts as a Proxmox cluster (corosync/HA)

## Current baseline (reuse)

| Piece | Location | Role |
|--------|----------|------|
| Singular cluster settings | `config.py` `Settings.cluster` | Active endpoint |
| Env apply + `.env` write | `admin/config_store.py` `apply_config` | Persist `PROXMOX_MCP_CLUSTER__*` |
| Secrets file | `secrets.local.json` (+ `PROXMOX_MCP_SECRETS_FILE`) | API token(s) by path |
| Process restart | `RuntimeController.request_restart` + `POST /admin/api/runtime/restart` | Docker restart policy recycles service |
| Config / Runtime UI | `web/src/pages/ConfigPage.tsx`, Runtime page | Existing apply + restart UX |

## Design

### 1. Host catalog

Persist a list of independent Proxmox **servers** (not cluster members):

| Field | Description |
|--------|-------------|
| `host_id` | Stable id (`pve-137`, `lab-nuc-1`) |
| `name` | Display label |
| `api_endpoint` | `https://host:8006` |
| `tls_verify` | bool |
| `credential_ref_path` | Key in secrets file (e.g. `clusters/pve-137/proxmox-api`) |
| `enabled` | Soft-hide from switcher without deleting |

**Storage:** JSON file next to admin config (e.g. `hosts.local.json`) **or** a dedicated section written via Admin API and stored on disk. Prefer a small durable file mounted like `secrets.local.json` so Docker recreate keeps the catalog. Do **not** require a new DB table for v1.

**Seed:** On first run, if catalog empty and `Settings.cluster` is set, create one catalog entry from the current singular cluster + its `credential_ref.path`.

### 2. Active host

Exactly one `active_host_id` at a time.

- Cold start: `active_host_id` from catalog default, or the seeded entry, or env `PROXMOX_MCP_ACTIVE_HOST_ID` if set.
- Runtime truth for Proxmox connectivity remains **`Settings.cluster`** (endpoint, name, tls, credential_ref) after a successful switch+restart.
- Overview / header always show **Managing: {name} ({api_endpoint})**.

### 3. Switch flow (WebUI)

1. Operator opens **Servers** (Config section or dedicated page) or a header **host switcher**.
2. Selects a different `host_id` → confirm dialog (“MCP will restart and manage only this host”).
3. Backend `POST /admin/api/hosts/{host_id}/activate` (name exact TBD):
   - Validate host exists, `enabled`, and secrets entry has `token_id` + `token_secret`.
   - Update active cluster env via existing apply path:
     - `PROXMOX_MCP_CLUSTER__API_ENDPOINT`
     - `PROXMOX_MCP_CLUSTER__TLS_VERIFY`
     - `PROXMOX_MCP_CLUSTER__NAME`
     - `PROXMOX_MCP_CLUSTER__CLUSTER_ID` ← `host_id`
     - `PROXMOX_MCP_CLUSTER__CREDENTIAL_REF__PATH` ← host’s `credential_ref_path`
   - Persist `active_host_id` in catalog metadata / env `PROXMOX_MCP_ACTIVE_HOST_ID`.
   - Call `runtime.request_restart()` (same as today’s restart API).
4. UI shows “Restarting…” and polls `/health/ready` (and/or `/admin/api/auth/me`) until back, then refreshes config banner.

If secrets are missing for the target host → **400** with clear message; do not restart.

### 4. Catalog CRUD (Admin API)

| Method | Purpose |
|--------|---------|
| `GET /admin/api/hosts` | List hosts + `active_host_id` + optional last-known health |
| `POST /admin/api/hosts` | Add host (id, name, endpoint, tls, credential path) |
| `PUT /admin/api/hosts/{host_id}` | Update metadata (not a silent activate) |
| `DELETE /admin/api/hosts/{host_id}` | Remove; refuse if it is the only host or currently active (must switch first) |
| `POST /admin/api/hosts/{host_id}/activate` | Switch + restart (above) |

Auth: existing admin session + CSRF. Audit: `hosts.activate`, `hosts.create`, etc.

**Secrets:** Per-host tokens remain on Secrets page (or host detail): write to that host’s `credential_ref_path`. Activating never copies secrets between paths; it only points `CREDENTIAL_REF__PATH` at the chosen path.

### 5. Optional light health (nice-to-have in same wave)

Before activate, optional probe `GET {api_endpoint}/api2/json/version` with that host’s token (short timeout). Show version/latency on the switcher. Failure → warn but allow force-activate (operator override) **or** block — default **warn + allow** so a temporarily down host can still be selected for config work.

### 6. MCP tool surface

No new Proxmox fan-out tools required for v1. Optional convenience (if cheap):

- `list_managed_hosts` (read catalog + which is active) — admin/internal or low-risk MCP tool  
- Not required if WebUI-only is enough for v1

Agents keep using the same tools; after restart they simply hit the newly active host.

## Error handling

| Case | Behavior |
|------|----------|
| Activate missing secrets | 400; no restart |
| Activate unknown / disabled host | 404 / 400 |
| Delete active host | 409; switch away first |
| Restart fails to come back | UI timeout + link to Runtime; Docker should still attempt restart policy |
| `.env` write fails | 500; no restart |

## Testing

- Unit: catalog seed from singular cluster; activate rewrites expected env keys; refuse activate without secrets; refuse delete active.
- API: CSRF-protected activate triggers `request_restart` (mock controller).
- Web: switcher lists hosts, confirm → activate → poll ready (mock).
- Manual: two host entries (current `.137` + second); switch and confirm `list_nodes` / storage reflect the selected API.

## Rollout

1. Catalog file + Admin API CRUD  
2. Activate → env apply + restart wiring  
3. WebUI switcher + banner  
4. Seed migration from current single cluster  
5. Docs: “two independent hosts, one active at a time”

## Success criteria

- Operator can register both Proxmox hosts and switch between them from the Admin WebUI.
- After switch+restart, MCP health is ready and Proxmox reads hit the selected endpoint only.
- No change to the singular in-process client model beyond which cluster settings are loaded at boot.
