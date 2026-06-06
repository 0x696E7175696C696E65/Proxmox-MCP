from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TypeVar

T = TypeVar("T")


class CircuitOpenError(RuntimeError):
    pass


@dataclass(slots=True)
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_seconds: int = 30
    _failure_count: int = 0
    _opened_at: datetime | None = None

    @property
    def open(self) -> bool:
        if self._opened_at is None:
            return False
        if datetime.now(UTC) - self._opened_at >= timedelta(seconds=self.recovery_seconds):
            self._failure_count = 0
            self._opened_at = None
            return False
        return True

    def before_call(self) -> None:
        if self.open:
            raise CircuitOpenError("Circuit is open")

    def record_success(self) -> None:
        self._failure_count = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.failure_threshold:
            self._opened_at = datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    attempts: int = 3
    backoff_seconds: float = 0.05

    async def run(self, operation: Callable[[], Awaitable[T]]) -> T:
        last_error: Exception | None = None
        for attempt in range(self.attempts):
            try:
                return await operation()
            except Exception as exc:
                last_error = exc
                if attempt + 1 >= self.attempts:
                    break
                await asyncio.sleep(self.backoff_seconds * (2**attempt))
        if last_error is None:
            raise RuntimeError("Retry policy executed without attempts")
        raise last_error
