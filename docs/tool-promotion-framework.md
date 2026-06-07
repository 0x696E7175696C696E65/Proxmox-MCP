# Tool Promotion Framework

Domain-completion tools begin guarded and move to live support only after their contract, tests, and lab evidence are complete.

## Promotion States

- `live_supported`: the tool has a real Proxmox API, SSH, hybrid, or internal execution path.
- `guarded_not_implemented`: the tool may expose dry-run metadata, but live execution must return `NOT_IMPLEMENTED`.
- `external_source_required`: the tool needs an external telemetry or repository source before returning live data.

## Promotion Checklist

Before replacing `NOT_IMPLEMENTED` behavior, every tool must define:

- Exact Proxmox endpoint or SSH command template.
- HTTP method or SSH execution mode.
- Required path fields and whether target metadata may supply them.
- Payload schema and rejected unrelated parameters.
- Dry-run preview with endpoint, payload, risk, impact, promotion status, and rollback guidance.
- Structured failure semantics for connector, policy, validation, and task errors.
- Unit tests with in-memory clients.
- Lab test proving the operation or proving a safe failure mode.
- Documentation showing the lab command and known limitations.

## Schema Expectations

Generated parameter schemas must be tool-specific:

- Required path fields are required unless safely target-backed (`node`, `vmid`, `storage_id`).
- Extra fields are forbidden.
- Unsafe path values, including `..`, are rejected before connector execution.
- Mutation payloads use the `payload` object until a domain pack replaces them with a narrower typed model.

## Replacement Criteria

A guarded tool can be promoted only when:

- `live_supported` becomes `true` because a real execution target exists.
- `promotion_status` becomes `live_supported`.
- Dry-run output includes rollback guidance appropriate to risk.
- Non-dry-run execution has unit coverage and lab evidence.
- Failed connector calls return structured errors and never false success.

If any requirement is incomplete, keep the tool guarded and document the reason.

## Backup Verification Contract

`verify_backup` is intentionally guarded. A backend can be promoted only after it defines:

- Backend type (`pve-local` or `pbs`) and repository/addressing fields.
- The exact verification source or command and expected success/failure mapping.
- Audit metadata proving which artifact was verified.
- A profile-specific lab run with a real backup artifact and sanitized release evidence.

Until then, live execution returns `NOT_IMPLEMENTED` with the backend and missing evidence requirements.

Restore paths must expose dry-run restore-preview evidence before promotion. A restore preview records the artifact, target type, target ID, storage target, artifact addressability, and confirms that mutation is still disabled.

## Storage Benchmark Contract

`benchmark_storage` is live-supported only for bounded benchmark runs:

- Runtime must be between 1 and 60 seconds.
- Artifact size must be between 4096 and 1073741824 bytes.
- Artifact paths must live under `/var/lib/vz/mcp-lab-*`.
- Execution uses the allowlisted `fio` executable with `--unlink=1` cleanup.
- Result evidence records artifact path, cleanup status, duration, size, and command hash.

Broader backend claims still require profile-specific lab evidence. `expand_storage`
remains guarded until each backend has resize, rollback, and cleanup proof.
