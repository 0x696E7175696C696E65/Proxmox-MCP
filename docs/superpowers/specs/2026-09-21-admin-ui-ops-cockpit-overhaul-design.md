# Admin UI Ops Cockpit Overhaul

**Date:** 2026-09-21  
**Status:** Approved  
**Approach:** Shell-first (ops cockpit + workflow polish + visual system)

## Goals

Blend denser ops UX, keyboard/workflow polish, and a stronger visual chrome without new backend APIs.

## Shell

- Left nav (Observe / Control) with approvals badge + health pulse in footer area
- Top bar: section label, `Ctrl+K` hint, live health/runtime chips
- Mobile: hamburger opens drawer sidebar; desktop sidebar fixed
- Restart-required banner retained

## Command palette (`Ctrl+K` / `Cmd+K`)

- Navigate to Overview, Tools, Audit, Health, Approvals, Secrets, Config, Runtime
- Filter by label; Enter to navigate; Esc to close

## Overview (cockpit)

- Status strip: Health, Runtime, Pending approvals, Restart
- Quick actions: Tools, Audit, Health, Approvals
- Cluster card + recent failures + recent audit events (last ~10 from existing audit API)

## Tools / Audit

- `xl` and up: master–detail split (list | detail panel)
- Below `xl`: keep Sheet drawer
- Audit: status filter chips (all / success / error / denied / started)
- Preserve risk chips, invokable-only, live SSE indicator, relative times

## Visual

- Denser spacing; consistent FormSection / metrics / empty states
- Amber primary for CTAs and active nav only

## Out of scope

- New backend endpoints, charts, theme toggle, multi-user admin UI
