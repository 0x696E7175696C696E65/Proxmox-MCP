from __future__ import annotations

import pytest

from proxmox_mcp.reliability import CircuitBreaker, CircuitOpenError, RetryPolicy


def test_circuit_breaker_opens_after_threshold() -> None:
    breaker = CircuitBreaker(failure_threshold=2, recovery_seconds=60)

    breaker.record_failure()
    breaker.record_failure()

    with pytest.raises(CircuitOpenError):
        breaker.before_call()


async def test_retry_policy_retries_until_success() -> None:
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise RuntimeError("temporary")
        return "ok"

    result = await RetryPolicy(attempts=3, backoff_seconds=0).run(operation)

    assert result == "ok"
    assert attempts == 2
