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

## 3. Validate before starting

```bash
python -m pip install -e ".[dev]"
proxmox-mcp validate-config
proxmox-mcp doctor
proxmox-mcp migrate
```

## 4. Start the stack

```bash
docker compose -f docker-compose.yml -f docker-compose.homelab.yml up --build
```

Readiness:

```bash
curl -fk -H "Authorization: Bearer $PROXMOX_MCP_SERVICE_TOKEN" https://localhost:8443/health/ready
```

## 5. Cursor MCP client

Point your MCP client at `https://localhost:8443` and send `Authorization: Bearer <service-token>` on each request.

## Optional observability profile

```bash
docker compose -f docker-compose.yml -f docker-compose.homelab.yml --profile observability up
```

Grafana listens on `http://localhost:3000`.
