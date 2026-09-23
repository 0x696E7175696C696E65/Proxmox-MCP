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
    required_approvals: int = 1
    resume_secret_hash: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovalValidationResult:
    valid: bool
    error_code: ErrorCode | None = None


@dataclass(frozen=True, slots=True)
class QueuedApproval:
    approval_request_id: str
    expires_at: datetime
    created: bool
    resume_secret: str | None = None


@dataclass(frozen=True, slots=True)
class DecideResult:
    approval: dict[str, object]
    approval_token: str | None = None
    quorum_pending: bool = False
    error_code: str | None = None


def _required_approvals_for_risk(
    risk_level: RiskLevel,
    *,
    dual_control_for_high: bool = True,
) -> int:
    if risk_level == "critical":
        return 2
    if risk_level == "high" and dual_control_for_high:
        return 2
    return 1


def _is_sod_violation(
    *,
    actor_user_id: str,
    actor_agent_id: str,
    decided_by: str,
    decided_by_user_id: str,
    linked_identity_groups: tuple[frozenset[str], ...] = (),
) -> bool:
    """Reject when the approving admin is the same principal as the requesting actor.

    Direct ID overlap and configured dual-persona linked groups both count.
    """
    approver_ids = {decided_by.strip().lower(), decided_by_user_id.strip().lower()} - {""}
    actor_ids = {actor_user_id.strip().lower(), actor_agent_id.strip().lower()} - {""}
    if approver_ids & actor_ids:
        return True
    for group in linked_identity_groups:
        if (approver_ids & group) and (actor_ids & group):
            return True
    return False


class InMemoryApprovalStore:
    """Test/dev store. Supports queue + decide + consume."""

    def __init__(
        self,
        approvals: tuple[StoredApproval, ...] = (),
        *,
        dual_control_for_high: bool = True,
        sod_linked_identity_groups: tuple[frozenset[str], ...] = (),
    ) -> None:
        self._by_id: dict[str, StoredApproval] = {a.approval_request_id: a for a in approvals}
        self._by_token_hash: dict[str, str] = {
            a.approval_token_hash: a.approval_request_id for a in approvals
        }
        self._summaries: dict[str, dict[str, object]] = {}
        self._decisions: dict[str, list[dict[str, object]]] = {}
        self._consumed_approval_ids: set[str] = set()
        self._lock = Lock()
        self._dual_control_for_high = dual_control_for_high
        self._sod_linked_identity_groups = sod_linked_identity_groups

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
                        resume_secret=None,
                    )
            request_id = str(uuid4())
            placeholder = hash_approval_token(secrets.token_urlsafe(32))
            resume_secret = secrets.token_urlsafe(32)
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
                required_approvals=_required_approvals_for_risk(
                    risk_level,
                    dual_control_for_high=self._dual_control_for_high,
                ),
                resume_secret_hash=hash_approval_token(resume_secret),
            )
            self._by_id[request_id] = approval
            self._by_token_hash[placeholder] = request_id
            self._decisions[request_id] = []
            if summary is not None:
                self._summaries[request_id] = summary
            return QueuedApproval(
                approval_request_id=request_id,
                expires_at=expires_at,
                created=True,
                resume_secret=resume_secret,
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

    async def get_by_id(self, approval_request_id: str) -> dict[str, object] | None:
        effective_now = datetime.now(UTC)
        with self._lock:
            self._expire_locked(effective_now)
            approval = self._by_id.get(approval_request_id)
            if approval is None:
                return None
            return self._public_row(approval)

    async def decide(
        self,
        approval_request_id: str,
        *,
        decision: Literal["approved", "rejected"],
        decided_by: str,
        reason: str | None = None,
        now: datetime | None = None,
        decided_by_user_id: str | None = None,
        step_up_audit_id: str | None = None,
    ) -> DecideResult | None:
        effective_now = datetime.now(UTC) if now is None else now
        approver_id = decided_by_user_id or decided_by
        with self._lock:
            approval = self._by_id.get(approval_request_id)
            if approval is None or approval.status != "pending":
                return None
            if approval.expires_at <= effective_now:
                self._by_id[approval_request_id] = StoredApproval(
                    **{**approval.__dict__, "status": "expired"}  # type: ignore[arg-type]
                )
                return None
            decisions = self._decisions.setdefault(approval_request_id, [])
            if any(str(item.get("approver_user_id")) == approver_id for item in decisions):
                row = self._public_row(approval)
                return DecideResult(
                    approval=row,
                    approval_token=None,
                    quorum_pending=True,
                    error_code="DUPLICATE_APPROVER",
                )

            if decision == "approved" and _is_sod_violation(
                actor_user_id=approval.actor_user_id,
                actor_agent_id=approval.actor_agent_id,
                decided_by=decided_by,
                decided_by_user_id=approver_id,
                linked_identity_groups=self._sod_linked_identity_groups,
            ):
                row = self._public_row(approval)
                return DecideResult(
                    approval=row,
                    approval_token=None,
                    quorum_pending=True,
                    error_code="SOD_VIOLATION",
                )

            decisions.append(
                {
                    "approver_user_id": approver_id,
                    "approver_username": decided_by,
                    "decision": decision,
                    "reason": reason,
                    "step_up_audit_id": step_up_audit_id,
                    "created_at": effective_now.isoformat(),
                }
            )

            if decision == "rejected":
                updated = StoredApproval(
                    **{**approval.__dict__, "status": "rejected"}  # type: ignore[arg-type]
                )
                self._by_id[approval_request_id] = updated
                row = self._public_row(updated)
                row["decided_by"] = decided_by
                row["reason"] = reason
                row["decided_at"] = effective_now.isoformat()
                return DecideResult(approval=row, approval_token=None)

            approved_votes = [item for item in decisions if item.get("decision") == "approved"]
            if len(approved_votes) < approval.required_approvals:
                row = self._public_row(approval)
                row["decided_by"] = decided_by
                row["reason"] = reason
                return DecideResult(approval=row, approval_token=None, quorum_pending=True)

            token = secrets.token_urlsafe(32)
            token_hash = hash_approval_token(token)
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
                status="approved",
                required_approvals=approval.required_approvals,
                resume_secret_hash=approval.resume_secret_hash,
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

    def consume_by_request_id(
        self,
        approval_request_id: str | None,
        *,
        actor: ActorIdentity,
        operation: str,
        target: Target,
        input_payload: object,
        risk_level: RiskLevel,
        risk_score: int,
        resume_secret: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalValidationResult:
        if approval_request_id is None:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")
        if resume_secret is None or not resume_secret.strip():
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

        with self._lock:
            approval = self._by_id.get(approval_request_id)
            if approval is None:
                return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

            if approval.approval_request_id in self._consumed_approval_ids:
                return ApprovalValidationResult(
                    valid=False,
                    error_code="APPROVAL_SCOPE_MISMATCH",
                )

            if not _resume_secret_matches(approval.resume_secret_hash, resume_secret):
                return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

            result = ApprovalValidator().validate(
                approval,
                approval_token=None,
                actor=actor,
                operation=operation,
                target=target,
                input_payload=input_payload,
                risk_level=risk_level,
                risk_score=risk_score,
                now=now,
                verify_token=False,
            )
            if result.valid:
                self._consumed_approval_ids.add(approval.approval_request_id)
                self._by_token_hash.pop(approval.approval_token_hash, None)

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
                    required_approvals=approval.required_approvals,
                    resume_secret_hash=approval.resume_secret_hash,
                )

    def _public_row(self, approval: StoredApproval) -> dict[str, object]:
        decisions = self._decisions.get(approval.approval_request_id, [])
        approved_count = sum(1 for item in decisions if item.get("decision") == "approved")
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
            "required_approvals": approval.required_approvals,
            "approval_count": approved_count,
            "decisions": [
                {
                    "approver_username": item.get("approver_username"),
                    "decision": item.get("decision"),
                    "created_at": item.get("created_at"),
                }
                for item in decisions
            ],
        }
        summary = self._summaries.get(approval.approval_request_id)
        if summary is not None:
            row["summary"] = summary
        return row


class DatabaseApprovalStore:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        dual_control_for_high: bool = True,
        sod_linked_identity_groups: tuple[frozenset[str], ...] = (),
    ) -> None:
        self._session_factory = session_factory
        self._dual_control_for_high = dual_control_for_high
        self._sod_linked_identity_groups = sod_linked_identity_groups

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
                    resume_secret=None,
                )
            request_id = str(uuid4())
            placeholder = hash_approval_token(secrets.token_urlsafe(32))
            resume_secret = secrets.token_urlsafe(32)
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
                    required_approvals=_required_approvals_for_risk(
                        risk_level,
                        dual_control_for_high=self._dual_control_for_high,
                    ),
                    resume_secret_hash=hash_approval_token(resume_secret),
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
                resume_secret=resume_secret,
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
            records = list((await session.scalars(statement)).all())
            out: list[dict[str, object]] = []
            for record in records:
                decisions = await _load_decisions(session, record.approval_request_id)
                out.append(_public_record(record, decisions=decisions))
            return out

    async def get_by_id(self, approval_request_id: str) -> dict[str, object] | None:
        async with self._session_factory() as session:
            await self._expire_pending(session, datetime.now(UTC))
            await session.commit()
            record = await session.get(ApprovalRecord, approval_request_id)
            if record is None:
                return None
            decisions = await _load_decisions(session, approval_request_id)
            return _public_record(record, decisions=decisions)

    async def decide(
        self,
        approval_request_id: str,
        *,
        decision: Literal["approved", "rejected"],
        decided_by: str,
        reason: str | None = None,
        now: datetime | None = None,
        decided_by_user_id: str | None = None,
        step_up_audit_id: str | None = None,
    ) -> DecideResult | None:
        from proxmox_mcp.persistence.models import ApprovalDecisionRecord

        effective_now = datetime.now(UTC) if now is None else now
        approver_id = decided_by_user_id or decided_by
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

            decisions = await _load_decisions(session, approval_request_id)
            if any(str(item.get("approver_user_id")) == approver_id for item in decisions):
                return DecideResult(
                    approval=_public_record(record, decisions=decisions),
                    approval_token=None,
                    quorum_pending=True,
                    error_code="DUPLICATE_APPROVER",
                )

            if decision == "approved" and _is_sod_violation(
                actor_user_id=record.actor_user_id,
                actor_agent_id=record.actor_agent_id,
                decided_by=decided_by,
                decided_by_user_id=approver_id,
                linked_identity_groups=self._sod_linked_identity_groups,
            ):
                return DecideResult(
                    approval=_public_record(record, decisions=decisions),
                    approval_token=None,
                    quorum_pending=True,
                    error_code="SOD_VIOLATION",
                )

            session.add(
                ApprovalDecisionRecord(
                    decision_id=f"approvaldec_{uuid4().hex}",
                    approval_request_id=approval_request_id,
                    approver_user_id=approver_id,
                    approver_username=decided_by,
                    decision=decision,
                    reason=reason,
                    step_up_audit_id=step_up_audit_id,
                    created_at=effective_now,
                )
            )

            if decision == "rejected":
                record.status = "rejected"
                record.decided_by = decided_by
                record.reason = reason
                record.decided_at = effective_now
                await session.commit()
                decisions = await _load_decisions(session, approval_request_id)
                return DecideResult(
                    approval=_public_record(record, decisions=decisions),
                    approval_token=None,
                )

            approved_count = sum(1 for item in decisions if item.get("decision") == "approved") + 1
            required = int(getattr(record, "required_approvals", 1) or 1)
            token: str | None = None
            if approved_count < required:
                record.decided_by = decided_by
                record.reason = reason
                await session.commit()
                decisions = await _load_decisions(session, approval_request_id)
                return DecideResult(
                    approval=_public_record(record, decisions=decisions),
                    approval_token=None,
                    quorum_pending=True,
                )

            token = secrets.token_urlsafe(32)
            record.status = "approved"
            record.decided_by = decided_by
            record.reason = reason
            record.decided_at = effective_now
            record.approval_token_hash = hash_approval_token(token)
            await session.commit()
            decisions = await _load_decisions(session, approval_request_id)
            return DecideResult(
                approval=_public_record(record, decisions=decisions),
                approval_token=token,
            )

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

    async def consume_by_request_id(
        self,
        approval_request_id: str | None,
        *,
        actor: ActorIdentity,
        operation: str,
        target: Target,
        input_payload: object,
        risk_level: RiskLevel,
        risk_score: int,
        resume_secret: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalValidationResult:
        if approval_request_id is None:
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")
        if resume_secret is None or not resume_secret.strip():
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

        async with self._session_factory() as session:
            record = await session.scalar(
                select(ApprovalRecord)
                .where(ApprovalRecord.approval_request_id == approval_request_id)
                .with_for_update()
            )
            if record is None:
                return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

            if record.consumed_at is not None:
                return ApprovalValidationResult(
                    valid=False,
                    error_code="APPROVAL_SCOPE_MISMATCH",
                )

            if not _resume_secret_matches(record.resume_secret_hash, resume_secret):
                return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

            approval = _stored_approval_from_record(record)
            result = ApprovalValidator().validate(
                approval,
                approval_token=None,
                actor=actor,
                operation=operation,
                target=target,
                input_payload=input_payload,
                risk_level=risk_level,
                risk_score=risk_score,
                now=now,
                verify_token=False,
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
        verify_token: bool = True,
    ) -> ApprovalValidationResult:
        effective_now = datetime.now(UTC) if now is None else now

        if effective_now >= approval.expires_at or approval.status == "expired":
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_EXPIRED")

        if approval.status != "approved":
            return ApprovalValidationResult(valid=False, error_code="APPROVAL_REQUIRED")

        if verify_token:
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


def _resume_secret_matches(stored_hash: str | None, provided: str) -> bool:
    if stored_hash is None or not stored_hash:
        return False
    return hmac.compare_digest(stored_hash, hash_approval_token(provided))


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
        required_approvals=int(getattr(record, "required_approvals", 1) or 1),
        resume_secret_hash=getattr(record, "resume_secret_hash", None),
    )


async def _load_decisions(
    session: AsyncSession,
    approval_request_id: str,
) -> list[dict[str, object]]:
    from proxmox_mcp.persistence.models import ApprovalDecisionRecord

    rows = (
        await session.scalars(
            select(ApprovalDecisionRecord)
            .where(ApprovalDecisionRecord.approval_request_id == approval_request_id)
            .order_by(ApprovalDecisionRecord.created_at.asc())
        )
    ).all()
    return [
        {
            "approver_user_id": row.approver_user_id,
            "approver_username": row.approver_username,
            "decision": row.decision,
            "reason": row.reason,
            "created_at": _aware(row.created_at).isoformat(),
        }
        for row in rows
    ]


def _public_record(
    record: ApprovalRecord,
    *,
    decisions: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    summary: object | None = None
    if record.summary_json:
        try:
            summary = json.loads(record.summary_json)
        except json.JSONDecodeError:
            summary = None
    decision_rows = decisions or []
    approved_count = sum(1 for item in decision_rows if item.get("decision") == "approved")
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
        "required_approvals": int(getattr(record, "required_approvals", 1) or 1),
        "approval_count": approved_count,
        "decisions": [
            {
                "approver_username": item.get("approver_username"),
                "decision": item.get("decision"),
                "created_at": item.get("created_at"),
            }
            for item in decision_rows
        ],
    }
