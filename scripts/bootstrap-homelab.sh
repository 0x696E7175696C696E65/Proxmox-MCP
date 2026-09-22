#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p certs/local/postgres certs/local/redis

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

if [[ ! -f secrets.local.json ]]; then
  cp secrets.local.json.example secrets.local.json
  echo "Created secrets.local.json from secrets.local.json.example"
fi

if command -v openssl >/dev/null 2>&1; then
  if [[ ! -f certs/local/ca.crt ]]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
      -keyout certs/local/ca.key -out certs/local/ca.crt \
      -subj "/CN=Proxmox MCP Local CA"
  fi
  for service in tls postgres redis; do
    if [[ ! -f "certs/local/${service}/tls.crt" ]]; then
      mkdir -p "certs/local/${service}"
      openssl req -newkey rsa:2048 -nodes \
        -keyout "certs/local/${service}/tls.key" \
        -out "certs/local/${service}/tls.csr" \
        -subj "/CN=proxmox-mcp-${service}"
      openssl x509 -req -in "certs/local/${service}/tls.csr" \
        -CA certs/local/ca.crt -CAkey certs/local/ca.key -CAcreateserial \
        -out "certs/local/${service}/tls.crt" -days 825 -sha256
      cp certs/local/ca.crt "certs/local/${service}/ca.crt"
    fi
  done
  cp certs/local/tls/tls.crt certs/local/tls.crt
  cp certs/local/tls/tls.key certs/local/tls.key
  echo "Generated local TLS material under certs/local/"
else
  echo "openssl not found; generate certs manually or set PROXMOX_MCP_TLS__GENERATE_SELF_SIGNED=true for dev"
fi

echo
echo "Next steps:"
echo "  1. Edit secrets.local.json with your Proxmox API token"
echo "  2. Edit .env with database password and service token"
echo "  3. docker compose -f docker-compose.yml -f docker-compose.homelab.yml up --build"
