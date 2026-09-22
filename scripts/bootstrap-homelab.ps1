$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

New-Item -ItemType Directory -Force -Path "certs/local/postgres", "certs/local/redis" | Out-Null

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
}

if (-not (Test-Path "secrets.local.json")) {
    Copy-Item "secrets.local.json.example" "secrets.local.json"
    Write-Host "Created secrets.local.json from secrets.local.json.example"
}

if (Get-Command openssl -ErrorAction SilentlyContinue) {
    if (-not (Test-Path "certs/local/ca.crt")) {
        openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes `
            -keyout "certs/local/ca.key" -out "certs/local/ca.crt" `
            -subj "/CN=Proxmox MCP Local CA"
    }
    foreach ($service in @("tls", "postgres", "redis")) {
        $serviceDir = "certs/local/$service"
        if (-not (Test-Path "$serviceDir/tls.crt")) {
            New-Item -ItemType Directory -Force -Path $serviceDir | Out-Null
            openssl req -newkey rsa:2048 -nodes `
                -keyout "$serviceDir/tls.key" `
                -out "$serviceDir/tls.csr" `
                -subj "/CN=proxmox-mcp-$service"
            openssl x509 -req -in "$serviceDir/tls.csr" `
                -CA "certs/local/ca.crt" -CAkey "certs/local/ca.key" -CAcreateserial `
                -out "$serviceDir/tls.crt" -days 825 -sha256
            Copy-Item "certs/local/ca.crt" "$serviceDir/ca.crt"
        }
    }
    Copy-Item "certs/local/tls/tls.crt" "certs/local/tls.crt"
    Copy-Item "certs/local/tls/tls.key" "certs/local/tls.key"
    Write-Host "Generated local TLS material under certs/local/"
} else {
    Write-Host "openssl not found; generate certs manually or set PROXMOX_MCP_TLS__GENERATE_SELF_SIGNED=true for dev"
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Edit secrets.local.json with your Proxmox API token"
Write-Host "  2. Edit .env with database password and service token"
Write-Host "  3. docker compose -f docker-compose.yml -f docker-compose.homelab.yml up --build"
