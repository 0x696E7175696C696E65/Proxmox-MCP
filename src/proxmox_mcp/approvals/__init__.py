from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any, Literal, cast
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.persistence.models import ApprovalRecord
from proxmox_mcp.schemas.envelope import ErrorCode, RiskLevel, Target

ApprovalStatus = Literal["pending", "approved", "rejected", "expired"]

DEFAULT_PENDING_TTL_SECONDS = 30 * 60


@dataclass(frozen=True, slots=True)
class StoredApproval:
    approval_request_id: str
    operation: str
    target_hash: str
    input_hash: str
    approval_token_hash: str
    actor_user_id: str
    actor_agent_id: str
    actor_tenant_id: str | None
    risk_level: RiskLevel
    risk_score: int
    expires_at: datetime
    status: ApprovalStatus


@dataclass(frozen=True, slots=True)
class ApprovalValidationResult:
    valid: bool
    error_code: ErrorCode | None = None


@dataclass(frozen=True, slots=True)
class QueuedApproval:
    approval_request_id: str
    expires_at: datetime
    created: bool


@dataclass(frozen=True, slots=True)
class DecideResult:
    approval: dict[str, object]
    approval_token: str | None = None


class InMemoryApprovalStore:
    """Test/dev store. Supports queue + decide + consume."""

    def __init__(self, approvals: tuple[StoredApproval, ...] = ()) -> None:
        self._by_id: dict[str, StoredApproval] = {a.approval_request_id: a for a in approvals}
        self._by_token_hash: dict[str, str] = {
            a.approval_token_hash: a.approval_request_id for a in approvals
        }
        self._summaries: dict[str, dict[str, object]] = {}
        self._consumed_approval_ids: set[str] = set()
        self._lock = Lock()

    def add(self, approval: StoredApproval) -> None:
        with self._lock:
            self._by_id[approval.approval_request_id] = approval
            self._by_token_hash[approval.approval_token_hash] = approval.approval_request_id

    async def queue_pending(
        self,
        *,
        operation: str,
        target: Target,
        input_payload: object,
        actor: ActorIdentity,
        risk_level: RiskLevel,
        risk_score: int,
        summary: dict[str, object] | None = None,
        ttl_seconds: int = DEFAULT_PENDING_TTL_SECONDS,
        now: datetime | None = None,
    ) -> QueuedApproval:
        effective_now = datetime.now(UTC) if now is None else now
        target_hash = canonical_json_hash(target.model_dump(mode="json"))
        input_hash = canonical_json_hash(input_payload)
        with self._lock:
            for existing in self._by_id.values():
                if (
                    existing.status == "pending"
                    and existing.expires_at > effective_now
                    and existing.operation == operation
                    and existing.target_hash == target_hash
                    and existing.input_hash == input_hash
                    and existing.actor_user_id == actor.user_id
                    and existing.actor_agent_id == actor.agent_id
                    and existing.actor_tenant_id == actor.tenant_id
                ):
                    return QueuedApproval(
                        approval_request_id=existing.approval_request_id,
                        expires_at=existing.expires_at,
                        created=False,
                    )
            request_id = str(uuid4())
            placeholder = hash_approval_token(secrets.token_urlsafe(32))
            expires_at = effective_now + timedelta(seconds=ttl_seconds)
            approval = StoredApproval(
                approval_request_id=request_id,
                operation=operation,
                target_hash=target_hash,
                input_hash=input_hash,
                approval_token_hash=placeholder,
                actor_user_id=actor.user_id,
                actor_agent_id=actor.agent_id,
                actor_tenant_id=actor.tenant_id,
                risk_level=risk_level,
                risk_score=risk_score,
                expires_at=expires_at,
                status="pending",
            )
            self._by_id[request_id] = approval
            self._by_token_hash[placeholder] = request_id
            if summary is not None:
                self._summaries[request_id] = summary
            return QueuedApproval(
                approval_request_id=request_id,
                expires_at=expires_at,
                created=True,
            )

    async def list_approvals(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        effective_now = datetime.now(UTC)
        with self._lock:
            self._expire_locked(effective_now)
            rows = list(self._by_id.values())
        rows.sort(key=lambda a: a.expires_at, reverse=True)
        out: list[dict[str, object]] = []
        for approval in rows:
            if status is not None and approval.status != status:
                continue
            out.append(self._public_row(approval))
            if len(out) >= min(max(limit, 1), 500):
                break
        return out

    async def decide(
        self,
        approval_request_id: str,
        *,
        decision: Literal["approved", "rejected"],
        decided_by: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> DecideResult | None:
        effective_now = datetime.now(UTC) if now is None else now
        with self._lock:
            approval = self._by_id.get(approval_request_id)
            if approval is None or approval.status != "pending":
                return None
            if approval.expires_at <= effective_now:
                self._by_id[approval_request_id] = StoredApproval(
                    **{**approval.__dict__, "status": "expired"}  # type: ignore[arg-type]
                )
                return None
            token: str | None = None
            token_hash = approval.approval_token_hash
            if decision == "approved":
                token = secrets.token_urlsafe(32)
                token_hash = hash_approval_token(token)
                # drop old placeholder mapping
                self._by_token_hash.pop(approval.approval_token_hash, None)
                self._by_token_hash[token_hash] = approval_request_id
            updated = StoredApproval(
                approval_request_id=approval.approval_request_id,
                operation=approval.operation,
                target_hash=approval.target_hash,
                input_hash=approval.input_hash,
                approval_token_hash=token_hash,
                actor_user_id=approval.actor_user_id,
                actor_agent_id=approval.actor_agent_id,
                actor_tenant_id=approval.actor_tenant_id,
                risk_level=approval.risk_level,
                risk_score=approval.risk_score,
                expires_at=approval.expires_at,
                status=decision,
            )
            self._by_id[approval_request_id] = updated
            row = self._public_row(updated)
            row["decided_by"] = decided_by
            row["reason"] = reason
            row["decided_at"] = effective_now.isoformat()
            return DecideResult(approval=row, approval_token=token)

    def consume(
        self,
        approval_token: str | None,
        *,
        actor: ActorIdentity,
        operation: str,
        target: Target,
        input_payload: object,
        risk_level: RiskLevel,
        risk_score: int,
        now: datetime | None = None,
    ) -> ApprovalValidationResult:
        if approval_token is None:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

        with self._lock:
            request_id = self._by_token_hash.get(hash_approval_token(approval_token))
            if request_id is None:
                return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")
            approval = self._by_id.get(request_id)
            if approval is None:
                return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

            if approval.approval_request_id in self._consumed_approval_ids:
                return ApprovalValidationResult(
                    valid=False,
                    error_code="APPROVAL_SCOPE_MISMATCH",
                )

            result = ApprovalValidator().validate(
                approval,
                approval_token=approval_token,
                actor=actor,
                operation=operation,
                target=target,
                input_payload=input_payload,
                risk_level=risk_level,
                risk_score=risk_score,
                now=now,
            )
            if result.valid:
                self._consumed_approval_ids.add(approval.approval_request_id)

            return result

    def _expire_locked(self, now: datetime) -> None:
        for request_id, approval in list(self._by_id.items()):
            if approval.status == "pending" and approval.expires_at <= now:
                self._by_id[request_id] = StoredApproval(
                    approval_request_id=approval.approval_request_id,
                    operation=approval.operation,
                    target_hash=approval.target_hash,
                    input_hash=approval.input_hash,
                    approval_token_hash=approval.approval_token_hash,
                    actor_user_id=approval.actor_user_id,
                    actor_agent_id=approval.actor_agent_id,
                    actor_tenant_id=approval.actor_tenant_id,
                    risk_level=approval.risk_level,
                    risk_score=approval.risk_score,
                    expires_at=approval.expires_at,
                    status="expired",
                )

    def _public_row(self, approval: StoredApproval) -> dict[str, object]:
        row: dict[str, object] = {
            "approval_request_id": approval.approval_request_id,
            "operation": approval.operation,
            "actor_user_id": approval.actor_user_id,
            "actor_agent_id": approval.actor_agent_id,
            "risk_level": approval.risk_level,
            "risk_score": approval.risk_score,
            "expires_at": approval.expires_at.isoformat(),
            "status": approval.status,
            "consumed_at": None,
        }
        summary = self._summaries.get(approval.approval_request_id)
        if summary is not None:
            row["summary"] = summary
        return row


class DatabaseApprovalStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def add(self, approval: StoredApproval, *, summary_json: str | None = None) -> None:
        record = ApprovalRecord(
            approval_request_id=approval.approval_request_id,
            operation=approval.operation,
            target_hash=approval.target_hash,
            input_hash=approval.input_hash,
            approval_token_hash=approval.approval_token_hash,
            actor_user_id=approval.actor_user_id,
            actor_agent_id=approval.actor_agent_id,
            actor_tenant_id=approval.actor_tenant_id,
            risk_level=approval.risk_level,
            risk_score=approval.risk_score,
            expires_at=approval.expires_at,
            status=approval.status,
            summary_json=summary_json,
        )
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()

    async def queue_pending(
        self,
        *,
        operation: str,
        target: Target,
        input_payload: object,
        actor: ActorIdentity,
        risk_level: RiskLevel,
        risk_score: int,
        summary: dict[str, object] | None = None,
        ttl_seconds: int = DEFAULT_PENDING_TTL_SECONDS,
        now: datetime | None = None,
    ) -> QueuedApproval:
        effective_now = datetime.now(UTC) if now is None else now
        target_hash = canonical_json_hash(target.model_dump(mode="json"))
        input_hash = canonical_json_hash(input_payload)
        async with self._session_factory() as session:
            await self._expire_pending(session, effective_now)
            existing = await session.scalar(
                select(ApprovalRecord)
                .where(ApprovalRecord.status == "pending")
                .where(ApprovalRecord.operation == operation)
                .where(ApprovalRecord.target_hash == target_hash)
                .where(ApprovalRecord.input_hash == input_hash)
                .where(ApprovalRecord.actor_user_id == actor.user_id)
                .where(ApprovalRecord.actor_agent_id == actor.agent_id)
                .where(ApprovalRecord.expires_at > effective_now)
                .order_by(ApprovalRecord.expires_at.desc())
            )
            if existing is not None and existing.actor_tenant_id == actor.tenant_id:
                return QueuedApproval(
                    approval_request_id=existing.approval_request_id,
                    expires_at=_aware(existing.expires_at),
                    created=False,
                )
            request_id = str(uuid4())
            placeholder = hash_approval_token(secrets.token_urlsafe(32))
            expires_at = effective_now + timedelta(seconds=ttl_seconds)
            session.add(
                ApprovalRecord(
                    approval_request_id=request_id,
                    operation=operation,
                    target_hash=target_hash,
                    input_hash=input_hash,
                    approval_token_hash=placeholder,
                    actor_user_id=actor.user_id,
                    actor_agent_id=actor.agent_id,
                    actor_tenant_id=actor.tenant_id,
                    risk_level=risk_level,
                    risk_score=risk_score,
                    expires_at=expires_at,
                    status="pending",
                    summary_json=None
                    if summary is None
                    else json.dumps(summary, sort_keys=True, default=str),
                )
            )
            await session.commit()
            return QueuedApproval(
                approval_request_id=request_id,
                expires_at=expires_at,
                created=True,
            )

    async def list_approvals(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        async with self._session_factory() as session:
            await self._expire_pending(session, datetime.now(UTC))
            await session.commit()
            statement = select(ApprovalRecord).order_by(ApprovalRecord.expires_at.desc())
            if status is not None:
                statement = statement.where(ApprovalRecord.status == status)
            statement = statement.limit(min(max(limit, 1), 500))
            records = (await session.scalars(statement)).all()
        return [_public_record(r) for r in records]

    async def decide(
        self,
        approval_request_id: str,
        *,
        decision: Literal["approved", "rejected"],
        decided_by: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> DecideResult | None:
        effective_now = datetime.now(UTC) if now is None else now
        async with self._session_factory() as session:
            record = await session.scalar(
                select(ApprovalRecord)
                .where(ApprovalRecord.approval_request_id == approval_request_id)
                .with_for_update()
            )
            if record is None or record.status != "pending":
                return None
            if _aware(record.expires_at) <= effective_now:
                record.status = "expired"
                await session.commit()
                return None

            token: str | None = None
            values: dict[str, object] = {
                "status": decision,
                "decided_by": decided_by,
                "reason": reason,
                "decided_at": effective_now,
            }
            if decision == "approved":
                token = secrets.token_urlsafe(32)
                values["approval_token_hash"] = hash_approval_token(token)

            update_result = cast(
                CursorResult[Any],
                await session.execute(
                    update(ApprovalRecord)
                    .where(ApprovalRecord.approval_request_id == approval_request_id)
                    .where(ApprovalRecord.status == "pending")
                    .values(**values)
                ),
            )
            if update_result.rowcount != 1:
                await session.rollback()
                return None
            await session.commit()
            record = await session.get(ApprovalRecord, approval_request_id)
            if record is None:
                return None
            return DecideResult(approval=_public_record(record), approval_token=token)

    async def consume(
        self,
        approval_token: str | None,
        *,
        actor: ActorIdentity,
        operation: str,
        target: Target,
        input_payload: object,
        risk_level: RiskLevel,
        risk_score: int,
        now: datetime | None = None,
    ) -> ApprovalValidationResult:
        if approval_token is None:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

        token_hash = hash_approval_token(approval_token)
        async with self._session_factory() as session:
            record = await session.scalar(
                select(ApprovalRecord)
                .where(ApprovalRecord.approval_token_hash == token_hash)
                .with_for_update()
            )
            if record is None:
                return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

            if record.consumed_at is not None:
                return ApprovalValidationResult(
                    valid=False,
                    error_code="APPROVAL_SCOPE_MISMATCH",
                )

            approval = _stored_approval_from_record(record)
            result = ApprovalValidator().validate(
                approval,
                approval_token=approval_token,
                actor=actor,
                operation=operation,
                target=target,
                input_payload=input_payload,
                risk_level=risk_level,
                risk_score=risk_score,
                now=now,
            )
            if not result.valid:
                return result

            consumed_at = datetime.now(UTC) if now is None else now
            update_result = cast(
                CursorResult[Any],
                await session.execute(
                    update(ApprovalRecord)
                    .where(ApprovalRecord.approval_request_id == approval.approval_request_id)
                    .where(ApprovalRecord.consumed_at.is_(None))
                    .where(ApprovalRecord.status == "approved")
                    .values(consumed_at=consumed_at)
                ),
            )
            if update_result.rowcount != 1:
                await session.rollback()
                return ApprovalValidationResult(
                    valid=False,
                    error_code="APPROVAL_SCOPE_MISMATCH",
                )

            await session.commit()
            return result

    async def _expire_pending(self, session: AsyncSession, now: datetime) -> None:
        await session.execute(
            update(ApprovalRecord)
            .where(ApprovalRecord.status == "pending")
            .where(ApprovalRecord.expires_at <= now)
            .values(status="expired")
        )


class ApprovalValidator:
    def validate(
        self,
        approval: StoredApproval,
        *,
        approval_token: str | None,
        actor: ActorIdentity,
        operation: str,
        target: Target,
        input_payload: object,
        risk_level: RiskLevel,
        risk_score: int,
        now: datetime | None = None,
    ) -> ApprovalValidationResult:
        effective_now = datetime.now(UTC) if now is None else now

        if effective_now >= approval.expires_at or approval.status == "expired":
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_EXPIRED")

        if approval.status != "approved":
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

        if approval_token is None or not hmac.compare_digest(
            hash_approval_token(approval_token),
            approval.approval_token_hash,
        ):
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_SCOPE_MISMATCH")

        if actor.user_id != approval.actor_user_id or actor.agent_id != approval.actor_agent_id:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_SCOPE_MISMATCH")

        if actor.tenant_id != approval.actor_tenant_id:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_SCOPE_MISMATCH")

        if operation != approval.operation:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_SCOPE_MISMATCH")

        if risk_level != approval.risk_level or risk_score != approval.risk_score:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_SCOPE_MISMATCH")

        if canonical_json_hash(target.model_dump(mode="json")) != approval.target_hash:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_SCOPE_MISMATCH")

        if canonical_json_hash(input_payload) != approval.input_hash:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_SCOPE_MISMATCH")

        return ApprovalValidationResult(valid=True)


def canonical_json_hash(payload: object) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hash_approval_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _stored_approval_from_record(record: ApprovalRecord) -> StoredApproval:
    return StoredApproval(
        approval_request_id=record.approval_request_id,
        operation=record.operation,
        target_hash=record.target_hash,
        input_hash=record.input_hash,
        approval_token_hash=record.approval_token_hash,
        actor_user_id=record.actor_user_id,
        actor_agent_id=record.actor_agent_id,
        actor_tenant_id=record.actor_tenant_id,
        risk_level=cast(RiskLevel, record.risk_level),
        risk_score=record.risk_score,
        expires_at=_aware(record.expires_at),
        status=cast(ApprovalStatus, record.status),
    )


def _public_record(record: ApprovalRecord) -> dict[str, object]:
    summary: object | None = None
    if record.summary_json:
        try:
            summary = json.loads(record.summary_json)
        except json.JSONDecodeError:
            summary = None
    return {
        "approval_request_id": record.approval_request_id,
        "operation": record.operation,
        "actor_user_id": record.actor_user_id,
        "actor_agent_id": record.actor_agent_id,
        "risk_level": record.risk_level,
        "risk_score": record.risk_score,
        "expires_at": _aware(record.expires_at).isoformat(),
        "status": record.status,
        "consumed_at": None
        if record.consumed_at is None
        else _aware(record.consumed_at).isoformat(),
        "summary": summary,
        "decided_by": record.decided_by,
        "reason": record.reason,
        "decided_at": None if record.decided_at is None else _aware(record.decided_at).isoformat(),
    }
