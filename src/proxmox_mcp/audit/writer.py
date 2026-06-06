from __future__ import annotations

from typing import Protocol

from proxmox_mcp.audit.events import AuditEvent


class AuditWriter(Protocol):
    async def write(self, event: AuditEvent) -> None: ...


class InMemoryAuditWriter:
    def __init__(self, events: list[AuditEvent] | None = None) -> None:
        self.events = [] if events is None else events

    async def write(self, event: AuditEvent) -> None:
        self.events.append(event)
