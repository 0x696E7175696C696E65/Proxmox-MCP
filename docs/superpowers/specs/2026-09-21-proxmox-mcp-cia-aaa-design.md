# Proxmox MCP CIA + AAA Improvement Increment

**Date:** 2026-09-21  
**Status:** Approved  
**Approach:** Phased monolith (Confidentiality/AuthN → Integrity/AuthZ → Availability/Accounting)

## Goals

Close highest-value CIA triad and AAA gaps after the prior hardening pass, with CI-backed invariants. No new OIDC/Vault backends.

## AuthZ depth

- Admin roles: `admin` | `operator`
- Secrets reveal/update require password step-up

## Waves

### Wave 1 — Confidentiality + Authentication
- Expand redaction keys; sanitize `Settings.safe_dump`
- CSRF via `hmac.compare_digest`; Secure cookies in production
- Settings/`run` fail-closed when production + `auth_mode=development`
- Shallow public admin health; metrics not anonymous
- Dummy password verify on missing admin user

### Wave 2 — Integrity + Authorization
- `admin_users.role` migration; role gates; secrets step-up
- Admin tool invoke binds `AuthenticatedSession`
- Production empty RBAC fails closed; non-health internal tools guarded
- Approval decide/consume locks; config If-Match; idempotency IntegrityError

### Wave 3 — Availability + Accounting
- Secrets reveal rate limit; login/authz/MCP-auth audit
- Readiness reuses runtime pool; admin health 503 when not ready
- SPA: role on `/me`, step-up UX, hide admin-only actions

## Out of scope
Audit hash-chain, SIEM worker, Redis-distributed limits, ASGI global timeouts, multi-user CRUD UI.
