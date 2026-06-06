# Security Regression Harness Design

## Purpose

The project is preview-ready and now needs stronger security qualification before it can move toward production readiness. This increment turns the security model into repeatable CI-backed invariants so future tool additions cannot silently weaken authentication, RBAC, policy, approvals, audit evidence, secret hygiene, or encrypted transport assumptions.

The harness should prove security behavior, not merely increase test count. Each test must assert the protected outcome and the evidence trail that would matter in an enterprise incident review.

## Goals

- Add a deterministic security regression suite that runs in normal CI without live Proxmox credentials.
- Prove fail-closed behavior for unsafe calls, missing authorization, disabled dangerous operations, malformed secrets, plaintext network URLs, and incomplete TLS configuration.
- Prove approval tokens remain scoped to actor, tenant, target, input payload, operation, and risk, and are consumed once.
- Prove audit evidence is emitted for denied and executed tool calls with the authenticated actor and tenant.
- Prove secret-like values and private key paths do not leak through safe settings dumps, error responses, audit metadata, or structured tool outputs.
- Document the invariants covered by CI so the security posture remains explicit.

## Non-Goals

- Do not run live Proxmox mutation tests in this slice.
- Do not promote guarded Proxmox tools to live support.
- Do not add a new policy language, auth backend, SIEM transport, or secret provider.
- Do not make broad refactors outside the files needed to express and pass the security invariants.

## Design

### Security Invariant Suite

Add focused tests under `tests/security/` that compose the existing guard, registry, settings, TLS, approval, policy, secrets, and audit modules. The suite should prefer high-signal scenario tests over duplicating unit coverage already present in `tests/approvals`, `tests/policy`, `tests/secrets`, `tests/test_config.py`, and `tests/server/test_tls.py`.

The primary test modules should be:

- `tests/security/test_security_invariants.py`
- `tests/security/test_secret_redaction_invariants.py`
- `tests/security/test_transport_invariants.py`

If setup duplication grows, extract local fixtures or helper builders in `tests/security/conftest.py`. Helpers should stay test-local unless production code genuinely needs the abstraction.

### Invariant Categories

Authentication and RBAC:

- Requests whose actor does not match the authenticated session fail before handler execution.
- Missing RBAC assignment fails before handler execution.
- Denied executions emit `started` then `denied` audit statuses.
- Audit actor fields reflect the authenticated session when request identity is forged.

Dangerous operations and approvals:

- Dangerous operations fail when globally disabled.
- Approval-required operations fail without a valid approval token.
- Approval tokens cannot be reused.
- Approval tokens cannot be replayed against a different actor, tenant, target, payload, operation, or risk profile.

Policy:

- Deny rules override allow rules even if allow rules also match.
- Disabled policy rules have no effect.
- Approval policy decisions remain distinct from hard deny decisions.

Secrets and redaction:

- Missing secret providers fail closed.
- Development secrets remain unavailable in production mode by default.
- Malformed Vault-style payloads fail closed.
- Known secret values, approval tokens, and TLS private key paths do not appear in safe settings dumps, error payloads, audit metadata, or rendered structured outputs used by tests.

Transport and configuration:

- MCP runtime cannot start without TLS material when self-signed generation is disabled.
- Generated TLS metadata redacts the private key path.
- Proxmox API base URLs require `https://`.
- PostgreSQL URLs require TLS.
- Redis URLs require `rediss://`.

## Data Flow

Test scenarios should use the same control-plane path normal tools use:

1. Build a `ToolRequest` with actor, target, parameters, and options.
2. Build a `ToolExecutionContext` with settings, authenticated session, audit writer, and guard dependencies.
3. Register a deliberately small test tool in `ToolRegistry`.
4. Execute the tool through `ToolRegistry.execute`.
5. Assert response type, error code or success payload, handler execution state, and audit events.

This keeps the harness close to real MCP behavior while avoiding live infrastructure.

## Error Handling Expectations

Security failures should be explicit and structured. Tests should assert stable error codes such as `AUTHENTICATION_FAILED`, `RBAC_DENIED`, `DANGEROUS_OPERATION_DISABLED`, `APPROVAL_REQUIRED`, and approval scope mismatch codes where relevant.

When a test exposes a vague or lossy error, the implementation should improve the error at the source instead of weakening the assertion.

## Verification Plan

Focused verification:

```powershell
python -m pytest tests/security tests/approvals tests/policy tests/secrets tests/test_config.py tests/server/test_tls.py
```

Full local verification:

```powershell
python -m ruff format .
python -m ruff check .
python -m pyright
python -m pytest
```

CI expectation:

- Existing CI runtime checks continue to run the full suite.
- Distribution readiness continues to build and smoke-install the package and Docker image.
- No lab credentials are required for this increment.

## Documentation Updates

Update security-facing documentation after implementation:

- `docs/security-model.md`: add a short section describing CI-enforced security invariants.
- `docs/release-hardening.md`: update preview release gates and current evidence to include the security regression harness.
- `README.md`: mention the dedicated security invariant suite in validation status if the implementation changes the suite count.

## Acceptance Criteria

- Security invariant tests exist and pass locally.
- Full offline suite passes.
- CI remains green after push.
- The new tests prove handler non-execution for denied paths where applicable.
- Audit evidence is asserted for both denied and approved execution paths.
- Secret redaction checks include at least one realistic secret value and one TLS private key path.
- Documentation names the invariant categories covered by the harness.
