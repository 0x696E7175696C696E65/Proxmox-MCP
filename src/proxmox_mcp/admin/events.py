from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdminEventHub:
    _subscribers: list[asyncio.Queue[dict[str, Any]]] = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        message = {"type": event_type, "payload": payload}
        async with self._lock:
            dead: list[asyncio.Queue[dict[str, Any]]] = []
            for queue in self._subscribers:
                try:
                    queue.put_nowait(message)
                except asyncio.QueueFull:
                    dead.append(queue)
            for queue in dead:
                self._subscribers.remove(queue)

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            async with self._lock:
                if queue in self._subscribers:
                    self._subscribers.remove(queue)


def format_sse(event: dict[str, Any]) -> bytes:
    data = json.dumps(event, default=str)
    return f"data: {data}\n\n".encode()
