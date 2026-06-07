from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from proxmox_mcp.audit.events import AuditEvent
from proxmox_mcp.audit.writer import AuditWriter
from proxmox_mcp.persistence.models import SiemDeliveryRecord

MetricStatus = Literal["success", "error", "denied"]
SiemFormat = Literal["splunk", "elk", "graylog", "wazuh", "loki"]
SiemDeliveryStatus = Literal["pending", "in_progress", "delivered", "dead_lettered"]
REDACTED_VALUE = "**********"
_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "auth",
    "credential",
    "key_file",
    "password",
    "private_key",
    "secret",
    "token",
)
_PROMETHEUS_METRIC_NAME = re.compile(r"^[A-Za-z_:][A-Za-z0-9_:]*$")


class MetricsSink(Protocol):
    def record_tool_invocation(
        self,
        *,
        tool_name: str,
        connector: str,
        status: MetricStatus,
        duration_ms: int,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ToolInvocationMetric:
    tool_name: str
    connector: str
    status: MetricStatus
    duration_ms: int


@dataclass(frozen=True, slots=True)
class AlertRecord:
    name: str
    status: str
    severity: str | None
    starts_at: str
    labels: dict[str, object]
    annotations: dict[str, object]
    fingerprint: str | None = None
    ends_at: str | None = None
    generator_url: str | None = None


@dataclass(frozen=True, slots=True)
class ResourceTrend:
    resource_type: str
    resource_id: str
    metric: str
    range_seconds: int
    step_seconds: int
    samples: list[dict[str, object]]


@dataclass(frozen=True, slots=True)
class SiemDeliveryRecordData:
    delivery_id: str
    destination: str
    payload: dict[str, object]
    status: SiemDeliveryStatus
    attempt_count: int
    max_attempts: int
    next_retry_at: datetime
    delivered_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class AlertBackend(Protocol):
    async def get_recent_alerts(
        self,
        *,
        limit: int,
        tenant_id: str | None,
        cluster_id: str | None,
        node_id: str | None,
    ) -> list[AlertRecord]: ...


class TrendBackend(Protocol):
    async def get_resource_trends(
        self,
        *,
        resource_type: str,
        resource_id: str,
        metric: str,
        range_seconds: int,
        step_seconds: int,
        limit: int,
    ) -> list[ResourceTrend]: ...


class JsonGetter(Protocol):
    async def __call__(self, url: str, timeout_seconds: int) -> object: ...


class SiemDelivery(Protocol):
    async def deliver(self, destination: str, payload: dict[str, object]) -> None: ...


class SiemDeliveryQueue(Protocol):
    async def enqueue(
        self,
        *,
        destination: str,
        payload: dict[str, object],
    ) -> SiemDeliveryRecordData: ...


class ObservabilityBackendError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.details = {} if details is None else details


class SiemDeliveryError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class AlertmanagerAlertBackend:
    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: int = 10,
        json_get: JsonGetter | None = None,
    ) -> None:
        _require_https_url(base_url, "Alertmanager URL")
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._json_get = _default_json_get if json_get is None else json_get

    async def get_recent_alerts(
        self,
        *,
        limit: int,
        tenant_id: str | None,
        cluster_id: str | None,
        node_id: str | None,
    ) -> list[AlertRecord]:
        _ = tenant_id, cluster_id, node_id
        params = urlencode({"active": "true", "silenced": "false", "inhibited": "false"})
        payload = await self._json_get(
            f"{self._base_url}/api/v2/alerts?{params}",
            self._timeout_seconds,
        )
        if not isinstance(payload, list):
            raise ObservabilityBackendError(
                "Alertmanager returned an invalid alerts payload",
                retryable=False,
            )
        alerts: list[AlertRecord] = []
        for item in cast(list[object], payload):
            if isinstance(item, dict):
                alert = _alert_from_alertmanager(cast(dict[object, object], item))
                if _alert_matches_scope(
                    alert,
                    tenant_id=tenant_id,
                    cluster_id=cluster_id,
                    node_id=node_id,
                ):
                    alerts.append(alert)
                if len(alerts) >= limit:
                    break
        return alerts


class PrometheusTrendBackend:
    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: int = 10,
        json_get: JsonGetter | None = None,
    ) -> None:
        _require_https_url(base_url, "Prometheus URL")
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._json_get = _default_json_get if json_get is None else json_get

    async def get_resource_trends(
        self,
        *,
        resource_type: str,
        resource_id: str,
        metric: str,
        range_seconds: int,
        step_seconds: int,
        limit: int,
    ) -> list[ResourceTrend]:
        end = datetime.now(UTC)
        start = end - timedelta(seconds=range_seconds)
        params = urlencode(
            {
                "query": _scoped_prometheus_query(
                    metric,
                    resource_type=resource_type,
                    resource_id=resource_id,
                ),
                "start": str(int(start.timestamp())),
                "end": str(int(end.timestamp())),
                "step": str(step_seconds),
            }
        )
        payload = await self._json_get(
            f"{self._base_url}/api/v1/query_range?{params}",
            self._timeout_seconds,
        )
        if not isinstance(payload, dict):
            raise ObservabilityBackendError(
                "Prometheus returned an invalid query_range payload",
                retryable=False,
            )
        payload_mapping = cast(dict[object, object], payload)
        if payload_mapping.get("status") != "success":
            raise ObservabilityBackendError(
                "Prometheus returned an invalid query_range payload",
                retryable=False,
            )
        data = payload_mapping.get("data")
        if not isinstance(data, dict):
            raise ObservabilityBackendError("Prometheus response data is invalid", retryable=False)
        data_mapping = cast(dict[object, object], data)
        results = data_mapping.get("result")
        if not isinstance(results, list):
            raise ObservabilityBackendError("Prometheus result set is invalid", retryable=False)
        trends: list[ResourceTrend] = []
        for item in cast(list[object], results):
            if isinstance(item, dict):
                item_mapping = cast(dict[object, object], item)
                if not _prometheus_series_matches(
                    item_mapping,
                    resource_type=resource_type,
                    resource_id=resource_id,
                ):
                    continue
                trends.append(
                    _trend_from_prometheus(
                        item_mapping,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        metric=metric,
                        range_seconds=range_seconds,
                        step_seconds=step_seconds,
                    )
                )
                if len(trends) >= limit:
                    break
        return trends


class DatabaseSiemDeliveryQueue:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        max_attempts: int = 3,
        retry_delay_seconds: int = 0,
    ) -> None:
        self._session_factory = session_factory
        self._max_attempts = max_attempts
        self._retry_delay_seconds = retry_delay_seconds

    async def enqueue(
        self,
        *,
        destination: str,
        payload: dict[str, object],
    ) -> SiemDeliveryRecordData:
        now = datetime.now(UTC)
        record = SiemDeliveryRecord(
            delivery_id=f"siem_delivery_{uuid4().hex}",
            destination=destination,
            payload_json=cast(dict[str, object], _sanitize_for_delivery(payload)),
            status="pending",
            attempt_count=0,
            max_attempts=self._max_attempts,
            next_retry_at=now,
            delivered_at=None,
            last_error=None,
            created_at=now,
            updated_at=now,
        )
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()
            return _siem_delivery_from_record(record)

    async def claim_due(self, *, limit: int = 100) -> list[SiemDeliveryRecordData]:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            candidate_ids = (
                await session.scalars(
                    select(SiemDeliveryRecord.delivery_id)
                    .where(SiemDeliveryRecord.status == "pending")
                    .where(SiemDeliveryRecord.next_retry_at <= now)
                    .order_by(SiemDeliveryRecord.created_at.asc())
                    .limit(limit)
                )
            ).all()
            claimed: list[SiemDeliveryRecord] = []
            for delivery_id in candidate_ids:
                result = cast(
                    CursorResult[object],
                    await session.execute(
                        update(SiemDeliveryRecord)
                        .where(SiemDeliveryRecord.delivery_id == delivery_id)
                        .where(SiemDeliveryRecord.status == "pending")
                        .where(SiemDeliveryRecord.next_retry_at <= now)
                        .values(status="in_progress", updated_at=now)
                    ),
                )
                if result.rowcount != 1:
                    continue
                record = await session.scalar(
                    select(SiemDeliveryRecord).where(
                        SiemDeliveryRecord.delivery_id == delivery_id
                    )
                )
                if record is not None:
                    claimed.append(record)
            await session.commit()
            return [_siem_delivery_from_record(record) for record in claimed]

    async def mark_delivered(self, delivery_id: str) -> None:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            record = await _get_delivery_record(session, delivery_id)
            record.status = "delivered"
            record.delivered_at = now
            record.updated_at = now
            await session.commit()

    async def mark_failed(
        self,
        delivery_id: str,
        *,
        error: str,
        retryable: bool = True,
    ) -> SiemDeliveryRecordData:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            record = await _get_delivery_record(session, delivery_id)
            record.attempt_count += 1
            record.last_error = error
            record.updated_at = now
            if not retryable or record.attempt_count >= record.max_attempts:
                record.status = "dead_lettered"
            else:
                record.status = "pending"
                record.next_retry_at = now + timedelta(seconds=self._retry_delay_seconds)
            await session.commit()
            return _siem_delivery_from_record(record)

    async def get(self, delivery_id: str) -> SiemDeliveryRecordData:
        async with self._session_factory() as session:
            return _siem_delivery_from_record(await _get_delivery_record(session, delivery_id))

    async def deliver_due(self, delivery: SiemDelivery, *, limit: int = 100) -> None:
        for record in await self.claim_due(limit=limit):
            try:
                await delivery.deliver(record.destination, record.payload)
            except SiemDeliveryError as exc:
                await self.mark_failed(
                    record.delivery_id,
                    error=str(exc),
                    retryable=exc.retryable,
                )
            except Exception as exc:  # pragma: no cover - adapter exceptions vary
                await self.mark_failed(record.delivery_id, error=exc.__class__.__name__)
            else:
                await self.mark_delivered(record.delivery_id)


class SiemQueueingAuditWriter:
    def __init__(
        self,
        audit_writer: AuditWriter,
        delivery_queue: SiemDeliveryQueue,
        *,
        destination: str,
        format_name: SiemFormat = "splunk",
    ) -> None:
        self._audit_writer = audit_writer
        self._delivery_queue = delivery_queue
        self._destination = destination
        self._format_name: SiemFormat
        self._format_name = format_name

    async def write(self, event: AuditEvent) -> None:
        await self._audit_writer.write(event)
        payload = format_siem_event(
            format_name=self._format_name,
            event="audit",
            audit_event=event.model_dump(mode="json"),
        )
        try:
            await self._delivery_queue.enqueue(destination=self._destination, payload=payload)
        except Exception:
            return


@dataclass(frozen=True, slots=True)
class TraceSpan:
    trace_id: str
    span_id: str
    name: str
    attributes: dict[str, object]

    @classmethod
    def start(cls, name: str, **attributes: object) -> TraceSpan:
        return cls(
            trace_id=uuid4().hex,
            span_id=uuid4().hex[:16],
            name=name,
            attributes=attributes,
        )


def _empty_metrics() -> list[ToolInvocationMetric]:
    return []


@dataclass(slots=True)
class InMemoryMetricsRegistry:
    invocations: list[ToolInvocationMetric] = field(default_factory=_empty_metrics)

    def record_tool_invocation(
        self,
        *,
        tool_name: str,
        connector: str,
        status: MetricStatus,
        duration_ms: int,
    ) -> None:
        self.invocations.append(
            ToolInvocationMetric(
                tool_name=tool_name,
                connector=connector,
                status=status,
                duration_ms=duration_ms,
            )
        )

    def render_prometheus(self) -> str:
        lines = [
            "# HELP proxmox_mcp_tool_invocations_total Total MCP tool invocations.",
            "# TYPE proxmox_mcp_tool_invocations_total counter",
        ]
        counts: dict[tuple[str, str, MetricStatus], int] = {}
        for invocation in self.invocations:
            key = (invocation.tool_name, invocation.connector, invocation.status)
            counts[key] = counts.get(key, 0) + 1
        for (tool_name, connector, status), count in sorted(counts.items()):
            lines.append(
                "proxmox_mcp_tool_invocations_total"
                f'{{tool="{tool_name}",connector="{connector}",status="{status}"}} {count}'
            )

        lines.extend(
            [
                "# HELP proxmox_mcp_tool_invocation_duration_ms Last observed MCP tool duration.",
                "# TYPE proxmox_mcp_tool_invocation_duration_ms gauge",
            ]
        )
        for invocation in self.invocations:
            lines.append(
                "proxmox_mcp_tool_invocation_duration_ms"
                f'{{tool="{invocation.tool_name}",connector="{invocation.connector}",'
                f'status="{invocation.status}"}} {invocation.duration_ms}'
            )
        return "\n".join(lines) + "\n"


def structured_log(
    *,
    event: str,
    level: Literal["debug", "info", "warning", "error"] = "info",
    **fields: object,
) -> str:
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "level": level,
        "event": event,
        **fields,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def format_siem_event(
    *,
    format_name: SiemFormat,
    event: str,
    **fields: object,
) -> dict[str, object]:
    timestamp = datetime.now(UTC).isoformat()
    sanitized_fields = cast(dict[str, object], _sanitize_for_delivery(fields))
    payload = cast(
        dict[str, object],
        _sanitize_for_delivery({"timestamp": timestamp, "event": event, **sanitized_fields}),
    )
    if format_name == "splunk":
        return {"time": timestamp, "event": payload}
    if format_name == "elk":
        return {"@timestamp": timestamp, "event": {"action": event}, **sanitized_fields}
    if format_name == "graylog":
        return {
            "version": "1.1",
            "short_message": event,
            "timestamp": timestamp,
            **sanitized_fields,
        }
    if format_name == "wazuh":
        return {"timestamp": timestamp, "rule": {"groups": ["proxmox_mcp"]}, **payload}
    return {
        "streams": [
            {
                "stream": {"service": "proxmox-mcp", "event": event},
                "values": [
                    [str(int(datetime.now(UTC).timestamp() * 1_000_000_000)), json.dumps(payload)]
                ],
            }
        ]
    }


async def _default_json_get(url: str, timeout_seconds: int) -> object:
    return await asyncio.to_thread(_blocking_json_get, url, timeout_seconds)


def _blocking_json_get(url: str, timeout_seconds: int) -> object:
    request = Request(url, headers={"Accept": "application/json"}, method="GET")  # noqa: S310
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise ObservabilityBackendError(
            "External observability backend returned an error",
            retryable=exc.code >= 500,
            details={"status_code": exc.code},
        ) from exc
    except URLError as exc:
        raise ObservabilityBackendError(
            "External observability backend is unavailable",
            retryable=True,
            details={"reason": str(exc.reason)},
        ) from exc
    except json.JSONDecodeError as exc:
        raise ObservabilityBackendError(
            "External observability backend returned invalid JSON",
            retryable=False,
        ) from exc


def _alert_from_alertmanager(item: dict[object, object]) -> AlertRecord:
    labels = _object_mapping(item.get("labels"))
    annotations = _object_mapping(item.get("annotations"))
    status = _object_mapping(item.get("status"))
    return AlertRecord(
        name=str(labels.get("alertname", "unknown")),
        status=str(status.get("state", "unknown")),
        severity=None if labels.get("severity") is None else str(labels["severity"]),
        starts_at=str(item.get("startsAt", "")),
        ends_at=None if item.get("endsAt") is None else str(item["endsAt"]),
        labels=labels,
        annotations=annotations,
        fingerprint=None if item.get("fingerprint") is None else str(item["fingerprint"]),
        generator_url=None if item.get("generatorURL") is None else str(item["generatorURL"]),
    )


def _trend_from_prometheus(
    item: dict[object, object],
    *,
    resource_type: str,
    resource_id: str,
    metric: str,
    range_seconds: int,
    step_seconds: int,
) -> ResourceTrend:
    values = item.get("values")
    samples: list[dict[str, object]] = []
    if isinstance(values, list):
        for value in cast(list[object], values):
            if isinstance(value, list):
                sample = cast(list[object], value)
            elif isinstance(value, tuple):
                sample = list(cast(tuple[object, ...], value))
            else:
                continue
            if len(sample) != 2:
                continue
            timestamp = _to_float(sample[0])
            value_number = _to_float(sample[1])
            if timestamp is None or value_number is None:
                continue
            samples.append(
                {
                    "timestamp": datetime.fromtimestamp(timestamp, UTC).isoformat(),
                    "value": value_number,
                }
            )
    return ResourceTrend(
        resource_type=resource_type,
        resource_id=resource_id,
        metric=metric,
        range_seconds=range_seconds,
        step_seconds=step_seconds,
        samples=samples,
    )


def _alert_matches_scope(
    alert: AlertRecord,
    *,
    tenant_id: str | None,
    cluster_id: str | None,
    node_id: str | None,
) -> bool:
    return (
        _label_matches(alert.labels, ("tenant_id", "tenant"), tenant_id)
        and _label_matches(alert.labels, ("cluster_id", "cluster"), cluster_id)
        and _label_matches(alert.labels, ("node_id", "node", "instance"), node_id)
    )


def _label_matches(labels: dict[str, object], keys: tuple[str, ...], expected: str | None) -> bool:
    if expected is None:
        return True
    return any(str(labels.get(key)) == expected for key in keys if key in labels)


def _scoped_prometheus_query(
    metric: str,
    *,
    resource_type: str,
    resource_id: str,
) -> str:
    if not _PROMETHEUS_METRIC_NAME.fullmatch(metric):
        raise ObservabilityBackendError(
            "Prometheus metric must be an unscoped metric name",
            retryable=False,
        )
    return (
        f'{metric}{{resource_type="{_escape_promql_label_value(resource_type)}",'
        f'resource_id="{_escape_promql_label_value(resource_id)}"}}'
    )


def _prometheus_series_matches(
    item: dict[object, object],
    *,
    resource_type: str,
    resource_id: str,
) -> bool:
    labels = _object_mapping(item.get("metric"))
    return (
        str(labels.get("resource_type")) == resource_type
        and str(labels.get("resource_id")) == resource_id
    )


def _escape_promql_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _object_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    mapping = cast(dict[object, object], value)
    return {str(key): item for key, item in mapping.items()}


def _to_float(value: object) -> float | None:
    if not isinstance(value, str | int | float):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _sanitize_for_delivery(value: object) -> object:
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        mapping = cast(dict[object, object], value)
        for key, item in mapping.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                sanitized[key_text] = REDACTED_VALUE
            else:
                sanitized[key_text] = _sanitize_for_delivery(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_for_delivery(item) for item in cast(list[object], value)]
    if isinstance(value, tuple):
        return tuple(_sanitize_for_delivery(item) for item in cast(tuple[object, ...], value))
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _require_https_url(value: str, label: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "https":
        raise ValueError(f"{label} must use https://")


async def _get_delivery_record(
    session: AsyncSession,
    delivery_id: str,
) -> SiemDeliveryRecord:
    record = await session.scalar(
        select(SiemDeliveryRecord).where(SiemDeliveryRecord.delivery_id == delivery_id)
    )
    if record is None:
        raise KeyError(delivery_id)
    return record


def _siem_delivery_from_record(record: SiemDeliveryRecord) -> SiemDeliveryRecordData:
    return SiemDeliveryRecordData(
        delivery_id=record.delivery_id,
        destination=record.destination,
        payload=record.payload_json,
        status=cast(SiemDeliveryStatus, record.status),
        attempt_count=record.attempt_count,
        max_attempts=record.max_attempts,
        next_retry_at=record.next_retry_at,
        delivered_at=record.delivered_at,
        last_error=record.last_error,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )
