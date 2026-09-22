# Multi-Host Switch + Restart Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators register independent Proxmox hosts and switch the active one from the Admin WebUI, rewriting cluster env + credential path and restarting MCP so tools target only that host.

**Architecture:** File-backed host catalog (`hosts.local.json`) + Admin API CRUD/activate. Activate maps a host into existing singular `Settings.cluster` env keys and calls `RuntimeController.request_restart()`. WebUI: header host switcher, Servers page, confirm + full-screen restart overlay with health polling. No in-process multi-client.

**Tech Stack:** Python 3.13, Starlette admin API, pydantic Settings, React + Vite admin SPA, Docker Compose (`restart: unless-stopped`), pytest + vitest.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-22-multi-host-switch-restart-design.md`
- One active Proxmox API client per process (singular `Settings.cluster`)
- No cross-host migrate / fan-out inventory / corosync cluster semantics
- Activate requires secrets (`token_id` + `token_secret`) at the host’s `credential_ref_path` or return 400 without restart
- Cannot delete the active host or the last remaining host (409)
- Auth: admin session + CSRF; activate/CRUD admin-role only (same as secrets/restart)
- Do not commit unless the user explicitly asks
- UX must feel intentional: always-visible “Managing: …” control, confirm before restart, polished restart wait state, secrets-ready + health cues on each host

## File map

| File | Responsibility |
|------|----------------|
| `src/proxmox_mcp/admin/hosts_store.py` | Catalog load/save/seed + activate env mapping |
| `src/proxmox_mcp/admin/hosts.py` | HTTP handlers for `/admin/api/hosts*` |
| `src/proxmox_mcp/admin/config_store.py` | Extend `AdminConfigUpdate` with `cluster_id` + `credential_ref_path` |
| `src/proxmox_mcp/admin/app.py` | Wire routes + mount `HostCatalog` on `AdminAppState` |
| `src/proxmox_mcp/server/runtime.py` | Construct catalog path; seed on boot; attach to admin state |
| `docker-compose.homelab.yml` | Mount `./hosts.local.json` + optional `PROXMOX_MCP_HOSTS_FILE` / `ACTIVE_HOST_ID` |
| `web/src/api.ts` | Host API client + types |
| `web/src/pages/ServersPage.tsx` | Catalog CRUD + activate UX |
| `web/src/components/host-switcher.tsx` | Header popover switcher |
| `web/src/components/host-restart-overlay.tsx` | Full-screen restart + poll |
| `web/src/App.tsx` / `app-topbar.tsx` / `command-palette.tsx` | Nav + topbar integration |
| `tests/admin/test_hosts_store.py` | Catalog/activate unit tests |
| `tests/admin/test_hosts_api.py` | API tests (mock restart) |
| `web/src/hosts.test.ts` | Client/helper vitest |

---

### Task 1: Host catalog store (seed + CRUD + activate mapping)

**Files:**
- Create: `src/proxmox_mcp/admin/hosts_store.py`
- Modify: `src/proxmox_mcp/admin/config_store.py` (extend `AdminConfigUpdate` mapping)
- Test: `tests/admin/test_hosts_store.py`

**Interfaces:**
- Produces:
  - `HostRecord(host_id, name, api_endpoint, tls_verify, credential_ref_path, enabled=True)`
  - `HostCatalogState(hosts: list[HostRecord], active_host_id: str | None)`
  - `HostCatalogStore(path: Path, settings: Settings, secrets_loader, config_applier)`
  - `store.load() -> HostCatalogState`
  - `store.seed_from_settings_if_empty() -> HostCatalogState`
  - `store.upsert(record) -> HostRecord`
  - `store.delete(host_id) -> None` (raises `HostCatalogError`)
  - `store.secrets_ready(host_id) -> bool`
  - `store.activate(host_id) -> ActivatePlan` with fields rewritten for env (does **not** call restart)
- Consumes: `ConfigStore.apply_config`, secrets file via loader callback

- [ ] **Step 1: Write failing tests**

```python
# tests/admin/test_hosts_store.py
from pathlib import Path
import json
import pytest
from proxmox_mcp.admin.hosts_store import HostCatalogStore, HostRecord, HostCatalogError
from proxmox_mcp.config import Settings

def _settings(tmp_path: Path) -> Settings:
    # Build minimal Settings with cluster pointing at one endpoint;
    # prefer constructing via env monkeypatch used elsewhere in tests/admin.
    ...

def test_seed_creates_entry_from_singular_cluster(tmp_path, monkeypatch):
    hosts_path = tmp_path / "hosts.local.json"
    # arrange Settings.cluster with cluster_id=homelab, api_endpoint, credential path
    store = HostCatalogStore(path=hosts_path, ...)
    state = store.seed_from_settings_if_empty()
    assert len(state.hosts) == 1
    assert state.hosts[0].host_id == "homelab"
    assert state.active_host_id == "homelab"
    assert json.loads(hosts_path.read_text())["active_host_id"] == "homelab"

def test_activate_requires_secrets(tmp_path):
    store = ...  # host without token in secrets
    with pytest.raises(HostCatalogError, match="secrets"):
        store.activate("pve-b")

def test_activate_rewrites_cluster_env_fields(tmp_path, monkeypatch):
    applied = {}
    def fake_apply(update):
        applied.update(update.model_dump(exclude_none=True))
        return ...
    store = HostCatalogStore(..., apply_config=fake_apply, secrets={...})
    store.activate("pve-b")
    assert applied["cluster_api_endpoint"] == "https://192.168.10.200:8006"
    assert applied["cluster_id"] == "pve-b"
    assert applied["credential_ref_path"] == "clusters/pve-b/proxmox-api"
    assert applied["cluster_name"] == "PVE B"
    assert store.load().active_host_id == "pve-b"

def test_delete_active_raises():
    ...
    with pytest.raises(HostCatalogError, match="active"):
        store.delete("homelab")
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `uv run --extra dev pytest tests/admin/test_hosts_store.py -q --tb=short`  
Expected: import / not found failures for `hosts_store`

- [ ] **Step 3: Implement `hosts_store.py` + extend config mapping**

`AdminConfigUpdate` add:
```python
cluster_id: str | None = None
credential_ref_path: str | None = None
```

`apply_config` mapping add:
```python
"cluster_id": "PROXMOX_MCP_CLUSTER__CLUSTER_ID",
"credential_ref_path": "PROXMOX_MCP_CLUSTER__CREDENTIAL_REF__PATH",
```

Also set `PROXMOX_MCP_ACTIVE_HOST_ID` inside `HostCatalogStore.activate` via dotenv write (same `_write_dotenv` helpers — import from config_store or duplicate small helpers in hosts_store to avoid circular imports; prefer importing `_write_dotenv` / `_env_file_path` if already module-level).

Catalog JSON shape:
```json
{
  "active_host_id": "homelab",
  "hosts": [
    {
      "host_id": "homelab",
      "name": "Homelab Proxmox",
      "api_endpoint": "https://192.168.10.137:8006",
      "tls_verify": false,
      "credential_ref_path": "clusters/homelab/proxmox-api",
      "enabled": true
    }
  ]
}
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `uv run --extra dev pytest tests/admin/test_hosts_store.py -q --tb=short`  
Expected: all PASS

---

### Task 2: Admin HTTP API for hosts + optional version probe

**Files:**
- Create: `src/proxmox_mcp/admin/hosts.py`
- Modify: `src/proxmox_mcp/admin/app.py` (routes + `AdminAppState.host_catalog`)
- Modify: `src/proxmox_mcp/server/runtime.py` (construct store, seed, attach)
- Modify: `docker-compose.homelab.yml` (mount hosts file)
- Test: `tests/admin/test_hosts_api.py`

**Interfaces:**
- Consumes: `HostCatalogStore` from Task 1; `RuntimeController.request_restart`
- Produces routes:
  - `GET /admin/api/hosts` → `{ hosts: [...], active_host_id, each host includes secrets_ready: bool, health?: {ok, version?, latency_ms?, error?} }`
  - `POST /admin/api/hosts` body `HostRecord` fields
  - `PUT /admin/api/hosts/{host_id}`
  - `DELETE /admin/api/hosts/{host_id}`
  - `POST /admin/api/hosts/{host_id}/activate` → `{ ok, host_id, restarting: true, message }` then `runtime.request_restart()`
  - `POST /admin/api/hosts/{host_id}/probe` → health probe only (for UI refresh)

Probe: `urllib`/`httpx` GET `{api_endpoint}/api2/json/version` with `Authorization: PVEAPIToken={token_id}={token_secret}`, `verify=tls_verify`, timeout 3s. On failure return `ok: false` (activate still allowed with warn — UI shows banner).

- [ ] **Step 1: Write API tests** (pattern from `tests/admin/test_admin_control_plane.py`)

```python
def test_list_hosts_seeds_and_returns_active(admin_client):
    r = admin_client.get("/admin/api/hosts")
    assert r.status_code == 200
    body = r.json()
    assert body["active_host_id"]
    assert body["hosts"][0]["secrets_ready"] in (True, False)

def test_activate_missing_secrets_no_restart(admin_client, monkeypatch):
    # add host without secrets
    calls = []
    monkeypatch.setattr(runtime, "request_restart", lambda: calls.append("restart"))
    r = admin_client.post("/admin/api/hosts/pve-b/activate")
    assert r.status_code == 400
    assert calls == []

def test_activate_ok_restarts(admin_client, monkeypatch):
    calls = []
    monkeypatch.setattr(..., "request_restart", lambda: calls.append(1) or {"ok": True})
    r = admin_client.post("/admin/api/hosts/homelab/activate")
    assert r.status_code == 200
    assert r.json()["restarting"] is True
    assert calls == [1]
```

- [ ] **Step 2: Run — expect FAIL** (routes missing)

Run: `uv run --extra dev pytest tests/admin/test_hosts_api.py -q --tb=short`

- [ ] **Step 3: Implement handlers + wire state**

In `runtime.py` when building admin state:
```python
hosts_path = Path(os.environ.get("PROXMOX_MCP_HOSTS_FILE", "hosts.local.json"))
host_catalog = HostCatalogStore(path=hosts_path, settings=settings, config_store=config_store)
host_catalog.seed_from_settings_if_empty()
# AdminAppState(..., host_catalog=host_catalog)
```

Compose volume:
```yaml
- ./hosts.local.json:/run/proxmox-mcp/hosts/hosts.local.json:rw
```
Env: `PROXMOX_MCP_HOSTS_FILE: /run/proxmox-mcp/hosts/hosts.local.json`

Create empty `hosts.local.json` (`{"hosts":[],"active_host_id":null}`) in repo root if missing so Docker mount works (seed fills it).

Register routes next to existing admin routes; protect mutations with `_require_admin_role` + existing CSRF middleware.

Audit events: `hosts.create`, `hosts.update`, `hosts.delete`, `hosts.activate`, `hosts.probe`.

- [ ] **Step 4: Run API tests — PASS**

Run: `uv run --extra dev pytest tests/admin/test_hosts_api.py tests/admin/test_hosts_store.py -q --tb=short`

---

### Task 3: Web API client + restart overlay helper

**Files:**
- Modify: `web/src/api.ts`
- Create: `web/src/lib/wait-for-admin.ts`
- Test: `web/src/hosts.test.ts`

**Interfaces:**
- Produces:
```ts
export type ManagedHost = {
  host_id: string;
  name: string;
  api_endpoint: string;
  tls_verify: boolean;
  credential_ref_path: string;
  enabled: boolean;
  secrets_ready: boolean;
  health?: { ok: boolean; version?: string; latency_ms?: number; error?: string };
};
export type HostsResponse = { hosts: ManagedHost[]; active_host_id: string | null };

AdminApi.hosts()
AdminApi.createHost(body)
AdminApi.updateHost(hostId, body)
AdminApi.deleteHost(hostId)
AdminApi.activateHost(hostId)
AdminApi.probeHost(hostId)

waitForAdminReady(opts: { timeoutMs?: number; intervalMs?: number }): Promise<void>
// polls GET /admin/api/me until 200 or timeout
```

- [ ] **Step 1: Vitest for `waitForAdminReady` success/timeout**

- [ ] **Step 2: Implement api + helper**

- [ ] **Step 3: Run** `npm test -- --run web/src/hosts.test.ts` from `web/`  
Expected: PASS

---

### Task 4: Sophisticated WebUI — header switcher + Servers page + overlay

**Files:**
- Create: `web/src/components/host-switcher.tsx`
- Create: `web/src/components/host-restart-overlay.tsx`
- Create: `web/src/pages/ServersPage.tsx`
- Modify: `web/src/components/app-topbar.tsx`
- Modify: `web/src/App.tsx` (route `/servers`, nav item Server/HardDrive icon)
- Modify: `web/src/components/command-palette.tsx` (Servers entry)
- Modify: `web/src/pages/OverviewPage.tsx` (Managing card links to Servers)
- Modify: `web/src/pages/SecretsPage.tsx` (show credential path hint per active host; optional host selector when saving Proxmox token into a chosen path — minimum: document path of active host)

**UX requirements (intuitive + sophisticated):**
1. **Top bar host pill** — always shows active name + short host (e.g. IP). Click opens popover listing all hosts with: name, endpoint, secrets badge (ready/missing), health dot (ok/warn/unknown), **Active** check. Selecting another opens confirm dialog.
2. **Confirm dialog** — title “Switch managed server?”; body explains MCP will restart and only the chosen host will be managed; primary button “Switch & restart”; secondary Cancel. If `!secrets_ready`, primary disabled + link “Add token on Secrets”.
3. **Restart overlay** — full-viewport, non-dismissible while waiting: spinner, “Restarting MCP…”, active host name, elapsed seconds; poll `waitForAdminReady`; on success toast/banner “Now managing {name}” and clear overlay; on timeout show error + “Open Runtime” link + Retry poll.
4. **Servers page** — table/cards: add host form (id, name, URL, TLS, credential path defaulting to `clusters/{host_id}/proxmox-api`); edit; delete (disabled for active); “Probe” button; “Activate” button (same confirm+overlay flow). Empty state explains two independent hosts, one active.
5. **Visual hierarchy** — reuse existing shadcn Button/Dialog/Alert patterns; no new design system; match ops cockpit density.

- [ ] **Step 1: Implement components and wire App/topbar/nav**

- [ ] **Step 2: Manual smoke against running stack**  
  - Open https://localhost:8443/admin/servers  
  - Confirm seeded host matches `.137`  
  - Add second host entry (can use placeholder URL) without secrets → Activate disabled/400  
  - With secrets path filled, activate → overlay → health ready → banner updates

- [ ] **Step 3: Run** `cd web && npm test` and `npm run build`  
Expected: PASS / build OK

---

### Task 5: Compose + docs + regression

**Files:**
- Modify: `docker-compose.homelab.yml` (hosts volume + env)
- Create: `hosts.local.json` starter (`{"hosts":[],"active_host_id":null}`)
- Modify: `docs/quickstart-homelab.md` (short “Multiple Proxmox hosts” section)
- Modify: `.env.example` (`PROXMOX_MCP_HOSTS_FILE`, `PROXMOX_MCP_ACTIVE_HOST_ID`)
- Test: re-run admin control plane suite to ensure no break

- [ ] **Step 1: Compose mount + example env**

- [ ] **Step 2: Docs blurb** — two independent hosts; switcher restarts MCP; per-host tokens in secrets file

- [ ] **Step 3: Regression**

Run:
```text
uv run --extra dev pytest tests/admin/test_hosts_store.py tests/admin/test_hosts_api.py tests/admin/test_admin_control_plane.py -q --tb=short
cd web && npm test && npm run build
```
Expected: all PASS

- [ ] **Step 4: Rebuild stack and verify**

```text
docker compose -f docker-compose.yml -f docker-compose.homelab.yml -f docker-compose.windows.yml up --build -d
curl -fk https://localhost:8443/health/ready
```
Expected: ready; Admin Servers page lists seeded host

---

## Spec coverage checklist

| Spec item | Task |
|-----------|------|
| Host catalog file | 1, 5 |
| Seed from singular cluster | 1 |
| Active host + env rewrite including credential path | 1, 2 |
| Activate → restart | 2, 4 |
| CRUD API | 2 |
| Secrets required gate | 1, 2, 4 |
| Delete active / last host refused | 1, 2 |
| WebUI switcher + banner | 4 |
| Restart wait / poll | 3, 4 |
| Optional health probe | 2, 4 |
| No multi-client / no fan-out | Global (not implemented) |
| Compose mount | 5 |

## Placeholder scan

None intentional. Commit steps omitted (user: commit only when asked).
