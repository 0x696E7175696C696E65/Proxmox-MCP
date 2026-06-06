# Production Deployment Guide

## Deployment Modes

Enterprise Proxmox MCP should support:

- Local development with a development secret provider.
- Docker Compose for homelab and small team deployments.
- Kubernetes for HA and enterprise deployments.
- External PostgreSQL, Redis, and secret manager services for production.

## Required Services

- MCP server application.
- PostgreSQL 16+.
- Redis 7+.
- Secret backend.
- Proxmox VE API endpoint.
- Optional SIEM or log pipeline.
- Optional Prometheus, Grafana, Loki, and OpenTelemetry collector.

## Configuration

Configuration is environment-driven:

```yaml
server:
  bind_host: 0.0.0.0
  port: 8443
  environment: production
  tls:
    cert_file: /run/proxmox-mcp/tls/tls.crt
    key_file: /run/proxmox-mcp/tls/tls.key

database:
  url: postgresql+asyncpg://proxmox_mcp:REDACTED@postgres/proxmox_mcp?ssl=require

redis:
  url: rediss://redis:6379/0

security:
  auth_mode: oidc
  dangerous_operations:
    enabled: true
    require_approval: true
    log_full_command: true

secrets:
  provider: hashicorp_vault
  vault_addr: https://vault.example.com
```

No secrets should be committed to the repository. Production deployments should load sensitive values from a secret manager or orchestrator secret mechanism.

The MCP server is HTTPS-only. Production deployments must mount a certificate and
private key into the application container and set `PROXMOX_MCP_TLS__CERT_FILE`
and `PROXMOX_MCP_TLS__KEY_FILE`. PostgreSQL URLs must require TLS with
`ssl=require` or an equivalent verification mode, and Redis URLs must use
`rediss://`. Disposable lab and development deployments may set
`PROXMOX_MCP_TLS__GENERATE_SELF_SIGNED=true`, but clients must explicitly trust
the generated certificate.

## Docker Deployment

The Docker image should:

- Use a minimal Python runtime base.
- Run as a non-root user.
- Include only runtime dependencies.
- Expose health and metrics endpoints.
- Support read-only root filesystem where possible.
- Write temporary files to configured writable paths.

Example service layout:

```yaml
services:
  proxmox-mcp:
    image: ghcr.io/0x696e7175696c696e65/proxmox-mcp:latest
    environment:
      PROXMOX_MCP_DATABASE_URL: postgresql+asyncpg://proxmox_mcp:REDACTED@postgres/proxmox_mcp?ssl=require
      PROXMOX_MCP_REDIS_URL: rediss://redis:6379/0
      PROXMOX_MCP_SECRET_PROVIDER: hashicorp_vault
      PROXMOX_MCP_TLS__CERT_FILE: /run/proxmox-mcp/tls/tls.crt
      PROXMOX_MCP_TLS__KEY_FILE: /run/proxmox-mcp/tls/tls.key
    ports:
      - "8443:8443"
    volumes:
      - ./certs/local:/run/proxmox-mcp/tls:ro
    depends_on:
      - postgres
      - redis
```

## Kubernetes Deployment

Kubernetes production deployments should include:

- Deployment with at least two replicas.
- PodDisruptionBudget.
- HorizontalPodAutoscaler.
- Service.
- NetworkPolicy.
- ConfigMap for non-secret configuration.
- Secret or external secret reference for bootstrap credentials.
- TLS Secret mounted at `/run/proxmox-mcp/tls`.
- ServiceMonitor for Prometheus.
- OpenTelemetry collector sidecar or daemon integration.

Recommended pod controls:

- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- Drop Linux capabilities.
- Resource requests and limits.
- Liveness, readiness, and startup probes.

## High Availability Design

The MCP server is stateless except for PostgreSQL and Redis. Multiple replicas can serve requests concurrently when they share:

- PostgreSQL for durable records.
- Redis for locks, idempotency coordination, rate limits, cache, and circuit state.
- A common secret backend.
- A shared object store or durable volume for SSH recordings if recordings are stored outside PostgreSQL.

HA-sensitive workflows:

- Approval validation must be database-backed.
- Idempotency must use Redis locks plus durable records.
- SSH interactive sessions should be sticky to a single replica unless a session broker is introduced.
- Long-running Proxmox task polling should be resumable through stored tool invocation state.

## Network Security

Recommended network controls:

- Restrict MCP server ingress to trusted agent networks or gateways.
- Restrict egress to Proxmox API endpoints, SSH endpoints, PostgreSQL, Redis, secret backends, and observability sinks.
- Use TLS for MCP ingress, Proxmox API, database, secret backend, and external logs.
- Use known host verification for SSH.
- Pin or validate Proxmox API certificates in production.

## Observability

Expose:

- `/health/live`
- `/health/ready`
- `/metrics`
- OpenTelemetry traces.
- Structured JSON logs.

Important metrics:

- Tool invocation count and latency.
- Policy decisions by effect.
- Approval requests by status.
- Dangerous operations by outcome.
- Proxmox API failures.
- SSH session count and duration.
- Circuit breaker state.
- Audit write failures.
- Secret backend failures.

## SIEM Integration

Audit events should be forwardable to:

- Splunk.
- ELK.
- Graylog.
- Wazuh.
- Loki.

The primary database remains the authoritative audit source. SIEM export failures should be logged and retried, but should not block read-only tool execution. Required audit persistence failures should block mutating execution.

## Backup And Recovery

Back up:

- PostgreSQL database.
- Configuration.
- Policy definitions.
- SSH recording storage.
- Deployment manifests.

Do not back up raw secrets from secret managers through this application. Use the secret provider's own backup and recovery process.

Recovery runbook:

1. Restore PostgreSQL.
2. Restore Redis only if required for short-lived state; otherwise allow cache rebuild.
3. Reconnect secret backend.
4. Validate migrations.
5. Start MCP server in read-only mode.
6. Verify audit continuity.
7. Re-enable mutating tools after validation.

## Upgrade Strategy

- Use database migrations with forward-only production migrations.
- Run contract tests before upgrade.
- Drain old replicas before schema-incompatible releases.
- Keep tool schema compatibility for at least one minor release.
- Provide rollback instructions for application image and configuration.

## Production Hardening Checklist

- Authentication enabled.
- TLS configured.
- Secret backend configured.
- No development secret provider.
- Dangerous operations reviewed.
- Approval workflow configured.
- Audit sink configured.
- SIEM export tested.
- Prometheus scrape configured.
- PostgreSQL backups enabled.
- Redis persistence or HA configured as appropriate.
- Network policies applied.
- Proxmox credentials least-privileged.
- SSH known hosts pinned.
