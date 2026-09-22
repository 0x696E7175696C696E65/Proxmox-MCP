# Homelab Quickstart

This guide boots a local Docker Compose stack with TLS, PostgreSQL, Redis, service-token auth, and file-backed Proxmox credentials.

## 1. Bootstrap local files

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap-homelab.ps1
```

or on Linux/macOS:

```bash
bash scripts/bootstrap-homelab.sh
```

## 2. Configure secrets

Edit `secrets.local.json` using `secrets.local.json.example` as a template. Store your Proxmox API token under the path referenced by `PROXMOX_MCP_CLUSTER__CREDENTIAL_REF__PATH`.

Edit `.env`:

- `PROXMOX_MCP_SERVICE_TOKEN`
- `PROXMOX_MCP_POSTGRES_PASSWORD`
- `PROXMOX_MCP_CLUSTER__API_ENDPOINT`
- `PROXMOX_MCP_ADMIN_USERNAME`
- `PROXMOX_MCP_ADMIN_PASSWORD`

## 3. Validate before starting

```bash
python -m pip install -e ".[dev]"
proxmox-mcp validate-config
proxmox-mcp doctor
```

Homelab Compose applies migrations on container start (`proxmox-mcp migrate && serve`).
For a one-shot migrate against a running stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.homelab.yml run --rm --entrypoint proxmox-mcp proxmox-mcp migrate
```

## 4. Start the stack

```bash
docker compose -f docker-compose.yml -f docker-compose.homelab.yml up --build
```

On Windows, include the Windows TLS overlay:

```powershell
docker compose -f docker-compose.yml -f docker-compose.homelab.yml -f docker-compose.windows.yml up --build
```

Readiness:

```bash
curl -fk -H "Authorization: Bearer $PROXMOX_MCP_SERVICE_TOKEN" https://localhost:8443/health/ready
```

## 5. Admin control plane

Open `https://localhost:8443/admin` and sign in with the bootstrap admin username/password.

The UI provides:

- Live audit history of MCP tool calls
- Secure secrets and API token management
- Runtime config with hot-apply / restart banners
- **Servers** page and header host switcher for multiple independent Proxmox hosts

### Multiple Proxmox hosts

You can register more than one Proxmox node (each with its own API URL). Only **one** host is active at a time—the MCP process talks to that host only.

1. **Catalog file** — `hosts.local.json` in the repo root (gitignored). Docker Compose mounts it at `/run/proxmox-mcp/hosts/hosts.local.json`. On first boot, if the catalog is empty, the server seeds one entry from your `.env` cluster settings.
2. **Per-host tokens** — Store each host’s Proxmox API token in `secrets.local.json` under that host’s `credential_ref_path` (default `clusters/{host_id}/proxmox-api`). Switching to a host without a token is blocked until secrets are ready.
3. **Switching** — Use **Admin → Servers** or the **Managing:** pill in the top bar. Confirm **Switch & restart**; MCP restarts and reloads env so tools target the chosen host. `PROXMOX_MCP_ACTIVE_HOST_ID` in `.env` is updated on activate.

Optional env overrides (see `.env.example`): `PROXMOX_MCP_HOSTS_FILE`, `PROXMOX_MCP_ACTIVE_HOST_ID`.

## 6. Cursor MCP client

Point your MCP client at `https://localhost:8443/mcp` and send `Authorization: Bearer <service-token>` on each request.

## Optional observability profile

```bash
docker compose -f docker-compose.yml -f docker-compose.homelab.yml --profile observability up
```

Grafana listens on `http://localhost:3000`.
