# Proxmox MCP Hardening Increment (Security / Stability / Integrity)

**Date:** 2026-09-21  
**Status:** Approved  
**Approach:** Balanced A+B+C hardening (not full rewrite)

## Goals

Improve attack surface, failure resilience, and integrity/audit guarantees with CI-backed invariants.

## Scope

### A — Attack surface
- Constant-time service-token comparison
- Failed-auth rate limit (sliding window per client IP)
- Production environment fails closed when Proxmox `tls_verify=false`
- Document/confirm `/admin` API remains session-authenticated (public prefix only for SPA static + health)

### B — Failure resilience
- Proxmox HTTP: ensure timeouts and map connection/timeout failures into circuit breaker
- Structured tool error when circuit is open (not opaque failure)
- DB engine: `pool_pre_ping` + bounded pool; verify dispose on shutdown
- Redis client close on shutdown if open

### C — Integrity
- Approval consume: atomic single-consume under DB lock / status transition
- Audit: started → terminal status on guard deny paths covered by tests
- Idempotency: regression that failed attempt allows correct retry semantics where designed

## Out of scope
- New auth backends, Vault, SIEM redesign, tool catalog expansion

## Tests
- `tests/security/` extensions for rate limit, constant-time path, prod TLS verify
- `tests/reliability/` for circuit-open mapping / timeout classification
- Approval race / single-consume regression
