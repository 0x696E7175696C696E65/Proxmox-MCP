"""Capability role store helpers (JSON tool lists in PostgreSQL)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.persistence.models import CapabilityRoleRecord
from proxmox_mcp.rbac.capability import (
    SYSTEM_TEMPLATE_IDS,
    CapabilityRole,
    seed_grants_from_catalog,
    system_capability_templates,
)


def capability_from_record(record: CapabilityRoleRecord) -> CapabilityRole:
    return CapabilityRole(
        role_id=record.role_id,
        name=record.name,
        description=record.description or "",
        base_template=record.base_template,
        granted_tools=frozenset(json.loads(record.granted_tools_json or "[]")),
        denied_tools=frozenset(json.loads(record.denied_tools_json or "[]")),
        permission_seeds=frozenset(json.loads(record.permission_seeds_json or "[]")),
        system=bool(record.system),
        version=int(record.version or 1),
    )


def _dumps(values: frozenset[str] | set[str] | list[str]) -> str:
    return json.dumps(sorted(values), separators=(",", ":"))


class CapabilityRoleStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def ensure_system_roles(
        self,
        *,
        tool_names: list[str],
        tool_permissions: dict[str, str],
        tool_risks: dict[str, str],
    ) -> None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            for template in system_capability_templates():
                seeded = seed_grants_from_catalog(
                    template,
                    tool_names=tool_names,
                    tool_permissions=tool_permissions,
                    tool_risks=tool_risks,
                )
                existing = await session.get(CapabilityRoleRecord, seeded.role_id)
                if existing is None:
                    session.add(
                        CapabilityRoleRecord(
                            role_id=seeded.role_id,
                            name=seeded.name,
                            description=seeded.description,
                            base_template=seeded.base_template,
                            granted_tools_json=_dumps(seeded.granted_tools),
                            denied_tools_json=_dumps(seeded.denied_tools),
                            permission_seeds_json=_dumps(seeded.permission_seeds),
                            system=True,
                            version=seeded.version,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                elif existing.system and not json.loads(existing.granted_tools_json or "[]"):
                    existing.granted_tools_json = _dumps(seeded.granted_tools)
                    existing.updated_at = now
            await session.commit()

    async def list_roles(self) -> list[CapabilityRole]:
        async with self._session_factory() as session:
            rows = list(
                (
                    await session.scalars(
                        select(CapabilityRoleRecord).order_by(CapabilityRoleRecord.name.asc())
                    )
                ).all()
            )
        return [capability_from_record(r) for r in rows]

    async def get(self, role_id: str) -> CapabilityRole | None:
        async with self._session_factory() as session:
            record = await session.get(CapabilityRoleRecord, role_id)
        if record is None:
            return None
        return capability_from_record(record)

    async def create(
        self,
        *,
        name: str,
        description: str,
        granted_tools: list[str],
        denied_tools: list[str],
        base_template: str | None,
        allow_star: bool,
    ) -> CapabilityRole:
        if "*" in granted_tools and not allow_star:
            raise ValueError("Granting '*' requires break-glass allow_star")
        now = datetime.now(UTC)
        role = CapabilityRole(
            role_id=f"caprole_{uuid4().hex}",
            name=name.strip(),
            description=description.strip(),
            base_template=base_template,
            granted_tools=frozenset(t.strip() for t in granted_tools if t.strip()),
            denied_tools=frozenset(t.strip() for t in denied_tools if t.strip()),
            system=False,
        )
        async with self._session_factory() as session:
            session.add(
                CapabilityRoleRecord(
                    role_id=role.role_id,
                    name=role.name,
                    description=role.description,
                    base_template=role.base_template,
                    granted_tools_json=_dumps(role.granted_tools),
                    denied_tools_json=_dumps(role.denied_tools),
                    permission_seeds_json="[]",
                    system=False,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()
        return role

    async def update(
        self,
        role_id: str,
        *,
        name: str | None,
        description: str | None,
        granted_tools: list[str] | None,
        denied_tools: list[str] | None,
        allow_star: bool,
    ) -> CapabilityRole:
        async with self._session_factory() as session:
            record = await session.get(CapabilityRoleRecord, role_id)
            if record is None:
                raise LookupError("Role not found")
            if record.system:
                raise PermissionError("System roles are immutable")
            if granted_tools is not None and "*" in granted_tools and not allow_star:
                raise ValueError("Granting '*' requires break-glass allow_star")
            if name is not None:
                record.name = name.strip()
            if description is not None:
                record.description = description.strip()
            if granted_tools is not None:
                record.granted_tools_json = _dumps(
                    frozenset(t.strip() for t in granted_tools if t.strip())
                )
            if denied_tools is not None:
                record.denied_tools_json = _dumps(
                    frozenset(t.strip() for t in denied_tools if t.strip())
                )
            record.version = int(record.version or 1) + 1
            record.updated_at = datetime.now(UTC)
            await session.commit()
            await session.refresh(record)
            return capability_from_record(record)

    async def delete(self, role_id: str) -> None:
        async with self._session_factory() as session:
            record = await session.get(CapabilityRoleRecord, role_id)
            if record is None:
                raise LookupError("Role not found")
            if record.system:
                raise PermissionError("System roles cannot be deleted")
            await session.delete(record)
            await session.commit()


def resolve_system_role_id(coarse: str) -> str:
    return SYSTEM_TEMPLATE_IDS.get(coarse.strip().lower(), SYSTEM_TEMPLATE_IDS["viewer"])
