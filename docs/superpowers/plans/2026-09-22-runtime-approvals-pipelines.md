# Runtime & Approvals Pipelines Implementation Plan

> **For agentic workers:** Use task-by-task execution. Steps use checkbox (`- [ ]`) syntax.

**Goal:** End-to-end secure approvals (mint → decide → one-time token → consume) plus live policy Settings, AuthZ fixes, and Runtime step-up + reconnect overlay.

**Architecture:** Queue pending approvals without consumable tokens (A2); mint token on admin approve with step-up; shared live Settings holder for hot policy; admin-only gated config/restart.

**Tech Stack:** Python/FastAPI-style Starlette admin, SQLAlchemy approvals, React Admin SPA.

## Global Constraints

- Pending TTL default: 30 minutes
- Operators: read-only Approvals; no decide/policy/config mutations in this increment
- Never return approval_token from list APIs
- Step-up password required for decide, policy PUT, restart
- Fail closed if approval store unavailable

---

## Task 1: Live Settings holder + AuthZ on config/policy

**Files:** `server/app.py`, `admin/config_store.py`, `admin/app.py`, `admin/control.py`, tests

- [x] Add settings holder (or re-read `config_store.settings` in MCP context_factory each call)
- [x] After `apply_config`, update live dangerous_operations for guard
- [x] Reject operator `PUT /admin/api/config` for dangerous_ops, cluster, credential, actor, log_level (403)
- [x] Add step-up password to `PUT /admin/api/policy`
- [x] Tests: operator config denied; policy updates live settings

## Task 2: Approval mint + decide token (A2) + migration

**Files:** `approvals/__init__.py`, `persistence/models/approval.py`, migration, `security/__init__.py`, `admin/control.py`, `admin/app.py`

- [x] Migration: `decided_by`, `reason`, `decided_at`, optional `summary_json`
- [x] `queue_pending(...)` with idempotent fingerprint; placeholder token hash; consume rejects pending
- [x] Guard: on requires_approval without token → queue → return approval_request_id
- [x] `decide`: admin-only path + step-up; on approve mint T + hash; return token once
- [x] Lazy expire pending on list/consume
- [x] Tests: mint→list→approve→consume; reject; operator 403; no password fails

## Task 3: Approvals WebUI

**Files:** `web/src/pages/ApprovalsPage.tsx`, `api.ts`, step-up modal component

- [x] Detail drawer; status filter; step-up for decide/policy
- [x] Show one-time token after approve (copy once)
- [x] Hide decide/policy for operators
- [x] Faster poll when pending > 0

## Task 4: Runtime step-up + overlay + restart_required

**Files:** `admin/app.py`, `config_store.py`, `RuntimePage.tsx`, overlay reuse

- [x] Restart body requires password; don't clear restart_required until boot
- [x] Set restart_required on Proxmox token secret changes
- [x] RuntimePage: step-up modal + HostRestartOverlay-style wait
- [x] Tests for restart step-up / mark_restarted semantics

## Task 5: Regression tests + docs touch

- [x] HTTP admin tests for CSRF/role/step-up on decide/restart/policy
- [x] Brief note in quickstart or security-model if needed
