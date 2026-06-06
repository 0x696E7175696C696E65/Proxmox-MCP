from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Literal, cast

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.auth import ActorIdentity
from proxmox_mcp.persistence.models import ApprovalRecord
from proxmox_mcp.schemas.envelope import ErrorCode, RiskLevel, Target

ApprovalStatus = Literal["pending", "approved", "rejected", "expired"]


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


class InMemoryApprovalStore:
    def __init__(self, approvals: tuple[StoredApproval, ...] = ()) -> None:
        self._approvals_by_token_hash = {
            approval.approval_token_hash: approval for approval in approvals
        }
        self._consumed_approval_ids: set[str] = set()
        self._lock = Lock()

    def add(self, approval: StoredApproval) -> None:
        with self._lock:
            self._approvals_by_token_hash[approval.approval_token_hash] = approval

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
            approval = self._approvals_by_token_hash.get(hash_approval_token(approval_token))
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


class DatabaseApprovalStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def add(self, approval: StoredApproval) -> None:
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
        )
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()

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
                select(ApprovalRecord).where(ApprovalRecord.approval_token_hash == token_hash)
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


def _stored_approval_from_record(record: ApprovalRecord) -> StoredApproval:
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
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
        expires_at=expires_at,
        status=cast(ApprovalStatus, record.status),
    )
