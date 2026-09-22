from __future__ import annotations

from proxmox_mcp.security.rate_limit import SlidingWindowRateLimiter


def test_sliding_window_rate_limiter_blocks_after_threshold() -> None:
    limiter = SlidingWindowRateLimiter(max_failures=3, window_seconds=60.0)
    now = 1000.0

    assert limiter.is_limited("10.0.0.1", now=now) is False
    limiter.record_failure("10.0.0.1", now=now)
    limiter.record_failure("10.0.0.1", now=now + 1)
    limiter.record_failure("10.0.0.1", now=now + 2)

    assert limiter.is_limited("10.0.0.1", now=now + 3) is True
    assert limiter.is_limited("10.0.0.2", now=now + 3) is False


def test_sliding_window_rate_limiter_expires_and_resets() -> None:
    limiter = SlidingWindowRateLimiter(max_failures=2, window_seconds=10.0)
    now = 1000.0

    limiter.record_failure("client-a", now=now)
    limiter.record_failure("client-a", now=now + 1)
    assert limiter.is_limited("client-a", now=now + 2) is True

    assert limiter.is_limited("client-a", now=now + 12) is False

    limiter.record_failure("client-a", now=now + 12)
    limiter.reset("client-a")
    assert limiter.is_limited("client-a", now=now + 13) is False
