from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from time import monotonic
from typing import cast


def _empty_failure_buckets() -> dict[str, deque[float]]:
    return {}


@dataclass(slots=True)
class SlidingWindowRateLimiter:
    """Track failed attempts per key and block when the window threshold is hit."""

    max_failures: int = 10
    window_seconds: float = 60.0
    _failures: dict[str, deque[float]] = field(default_factory=_empty_failure_buckets)
    _lock: Lock = field(default_factory=Lock)

    def is_limited(self, key: str, *, now: float | None = None) -> bool:
        instant = monotonic() if now is None else now
        with self._lock:
            self._prune(key, instant)
            bucket = self._failures.get(key)
            return bucket is not None and len(bucket) >= self.max_failures

    def record_failure(self, key: str, *, now: float | None = None) -> None:
        instant = monotonic() if now is None else now
        with self._lock:
            bucket = self._failures.setdefault(key, deque())
            bucket.append(instant)
            self._prune(key, instant)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def _prune(self, key: str, now: float) -> None:
        bucket = self._failures.get(key)
        if bucket is None:
            return
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if not bucket:
            self._failures.pop(key, None)


# Shared limiters for failed MCP bearer auth and admin password login.
FAILED_AUTH_LIMITER = SlidingWindowRateLimiter(max_failures=10, window_seconds=60.0)
FAILED_ADMIN_LOGIN_LIMITER = SlidingWindowRateLimiter(max_failures=10, window_seconds=60.0)
# Failed step-up password checks (decide / policy / restart / secrets).
FAILED_ADMIN_STEP_UP_LIMITER = SlidingWindowRateLimiter(max_failures=5, window_seconds=60.0)


def client_ip_from_scope(scope: dict[str, object]) -> str:
    client = scope.get("client")
    if isinstance(client, tuple) and client:
        first = cast(object, client[0])
        if isinstance(first, str) and first:
            return first
    return "unknown"
