from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _new_audit_event_id() -> str:
    return f"audit_{uuid4().hex}"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cluster_id: str | None = None
    node_id: str | None = None
    resource_type: str
    resource_id: str
    metadata: dict[str, object] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=_new_audit_event_id)
    timestamp: datetime = Field(default_factory=_utc_now)
    event_type: str
    correlation_id: str
    tenant_id: str | None = None
    actor_user_id: str
    actor_agent_id: str
    tool_name: str
    operation: str
    target: AuditTarget
    result_status: Literal["started", "success", "error", "denied"]
    exit_code: int | None = None
    duration_ms: int | None = None
    error_code: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")

        return value.astimezone(UTC)
