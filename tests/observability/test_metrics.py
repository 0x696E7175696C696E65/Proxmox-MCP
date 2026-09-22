from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.observability import (
    AlertmanagerAlertBackend,
    DatabaseSiemDeliveryQueue,
    HttpJsonSiemDelivery,
    InMemoryMetricsRegistry,
    ObservabilityBackendError,
    PrometheusTrendBackend,
    SiemDelivery,
    SiemDeliveryError,
    SiemDeliveryRecordData,
    SiemQueueingAuditWriter,
    TraceSpan,
    format_siem_event,
    structured_log,
)
from proxmox_mcp.persistence.database import build_session_factory
from proxmox_mcp.persistence.models import Base


def test_metrics_registry_renders_prometheus_counters() -> None:
    registry = InMemoryMetricsRegistry()

    registry.record_tool_invocation(
        tool_name="list_nodes",
        connector="proxmox_api",
        status="success",
        duration_ms=12,
    )

    rendered = registry.render_prometheus()

    assert "proxmox_mcp_tool_invocations_total" in rendered
    assert 'tool="list_nodes"' in rendered
    assert 'connector="proxmox_api"' in rendered
    assert 'status="success"' in rendered


def test_structured_log_outputs_json() -> None:
    payload = json.loads(structured_log(event="tool.finished", request_id="req_1"))

    assert payload["event"] == "tool.finished"
    assert payload["level"] == "info"
    assert payload["request_id"] == "req_1"
    assert "timestamp" in payload


def test_trace_span_generates_trace_context() -> None:
    span = TraceSpan.start("tool.execute", tool_name="list_nodes")

    assert len(span.trace_id) == 32
    assert len(span.span_id) == 16
    assert span.attributes["tool_name"] == "list_nodes"


def test_siem_payloads_support_loki_and_splunk() -> None:
    splunk = format_siem_event(format_name="splunk", event="audit", request_id="req_1")
    loki = format_siem_event(format_name="loki", event="audit", request_id="req_1")

    assert "event" in splunk
    assert "streams" in loki


def test_loki_siem_payloads_redact_before_json_stringification() -> None:
    loki = format_siem_event(
        format_name="loki",
        event="audit",
        metadata={"api_token": "secret-value"},
    )

    assert "secret-value" not in str(loki)
    assert "**********" in str(loki)


async def test_alertmanager_backend_normalizes_recent_alerts() -> None:
    captured_urls: list[str] = []

    async def fake_json_get(url: str, timeout_seconds: int) -> object:
        captured_urls.append(url)
        assert timeout_seconds == 7
        return [
            {
                "labels": {
                    "alertname": "NodeDown",
                    "severity": "critical",
                    "tenant_id": "tenant-1",
                    "cluster": "lab",
                    "node": "pve-1",
                },
                "annotations": {"summary": "node unavailable"},
                "startsAt": "2026-06-06T00:00:00Z",
                "endsAt": "0001-01-01T00:00:00Z",
                "status": {"state": "active"},
                "fingerprint": "abc123",
                "generatorURL": "https://prometheus.example/graph",
            }
        ]

    backend = AlertmanagerAlertBackend(
        base_url="https://alerts.example",
        timeout_seconds=7,
        json_get=fake_json_get,
    )

    alerts = await backend.get_recent_alerts(
        limit=5,
        tenant_id="tenant-1",
        cluster_id="lab",
        node_id="pve-1",
    )

    assert captured_urls == [
        "https://alerts.example/api/v2/alerts?active=true&silenced=false&inhibited=false"
    ]
    assert alerts[0].name == "NodeDown"
    assert alerts[0].status == "active"
    assert alerts[0].severity == "critical"
    assert alerts[0].labels["node"] == "pve-1"


def test_http_json_siem_delivery_requires_https_destination() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        HttpJsonSiemDelivery(timeout_seconds=3).validate_destination("http://siem.example/ingest")


def test_http_json_siem_delivery_rejects_credential_bearing_destinations() -> None:
    delivery = HttpJsonSiemDelivery(timeout_seconds=3)

    with pytest.raises(ValueError, match="must not contain userinfo"):
        delivery.validate_destination("https://user:pass@siem.example/ingest")

    with pytest.raises(ValueError, match="credential-shaped query"):
        delivery.validate_destination("https://siem.example/ingest?token=value")


def test_siem_queueing_audit_writer_rejects_credential_bearing_destination() -> None:
    class Queue:
        async def enqueue(
            self,
            *,
            destination: str,
            payload: dict[str, object],
        ) -> SiemDeliveryRecordData:
            raise AssertionError("destination validation should happen before enqueue")

    with pytest.raises(ValueError, match="credential-shaped query"):
        SiemQueueingAuditWriter(
            InMemoryAuditWriter(),
            Queue(),
            destination="https://siem.example/ingest?token=value",
        )


async def test_http_json_siem_delivery_posts_redacted_payload() -> None:
    calls: list[tuple[str, dict[str, object], int]] = []

    async def fake_post(url: str, payload: dict[str, object], timeout_seconds: int) -> int:
        calls.append((url, payload, timeout_seconds))
        return 202

    delivery = HttpJsonSiemDelivery(timeout_seconds=3, json_post=fake_post)

    await delivery.deliver(
        "https://siem.example/ingest",
        {"event": "audit", "metadata": {"api_token": "secret-value"}},
    )

    assert calls == [
        (
            "https://siem.example/ingest",
            {"event": "audit", "metadata": {"api_token": "**********"}},
            3,
        )
    ]


async def test_http_json_siem_delivery_maps_server_errors_to_retryable_failure() -> None:
    async def fake_post(url: str, payload: dict[str, object], timeout_seconds: int) -> int:
        _ = url, payload, timeout_seconds
        return 503

    delivery = HttpJsonSiemDelivery(json_post=fake_post)

    with pytest.raises(SiemDeliveryError) as exc_info:
        await delivery.deliver("https://siem.example/ingest", {"event": "audit"})

    assert exc_info.value.retryable is True


async def test_prometheus_backend_normalizes_bounded_trends() -> None:
    captured_urls: list[str] = []

    async def fake_json_get(url: str, timeout_seconds: int) -> object:
        captured_urls.append(url)
        assert timeout_seconds == 9
        return {
            "status": "success",
            "data": {
                "result": [
                    {
                        "metric": {
                            "__name__": "cpu_usage",
                            "resource_type": "vm",
                            "resource_id": "100",
                        },
                        "values": [[1_780_700_400, "0.42"], [1_780_700_460, "0.43"]],
                    }
                ]
            },
        }

    backend = PrometheusTrendBackend(
        base_url="https://prometheus.example",
        timeout_seconds=9,
        json_get=fake_json_get,
    )

    trends = await backend.get_resource_trends(
        resource_type="vm",
        resource_id="100",
        metric="cpu_usage",
        range_seconds=3600,
        step_seconds=60,
        limit=1,
    )

    assert "/api/v1/query_range?" in captured_urls[0]
    assert "resource_type" in captured_urls[0]
    assert "resource_id" in captured_urls[0]
    assert trends[0].samples == [
        {"timestamp": "2026-06-05T23:00:00+00:00", "value": 0.42},
        {"timestamp": "2026-06-05T23:01:00+00:00", "value": 0.43},
    ]


async def test_alertmanager_backend_filters_alerts_to_requested_scope() -> None:
    async def fake_json_get(url: str, timeout_seconds: int) -> object:
        _ = url, timeout_seconds
        return [
            {
                "labels": {
                    "alertname": "WrongNode",
                    "tenant_id": "tenant-1",
                    "cluster": "lab",
                    "node": "pve-2",
                },
                "startsAt": "2026-06-06T00:00:00Z",
                "status": {"state": "active"},
            },
            {
                "labels": {
                    "alertname": "NodeDown",
                    "tenant_id": "tenant-1",
                    "cluster": "lab",
                    "node": "pve-1",
                },
                "startsAt": "2026-06-06T00:00:00Z",
                "status": {"state": "active"},
            },
        ]

    backend = AlertmanagerAlertBackend(
        base_url="https://alerts.example",
        json_get=fake_json_get,
    )

    alerts = await backend.get_recent_alerts(
        limit=10,
        tenant_id="tenant-1",
        cluster_id="lab",
        node_id="pve-1",
    )

    assert [alert.name for alert in alerts] == ["NodeDown"]


async def test_prometheus_backend_filters_unscoped_series_from_results() -> None:
    async def fake_json_get(url: str, timeout_seconds: int) -> object:
        _ = url, timeout_seconds
        return {
            "status": "success",
            "data": {
                "result": [
                    {
                        "metric": {"resource_type": "vm", "resource_id": "200"},
                        "values": [[1_780_700_400, "0.99"]],
                    },
                    {
                        "metric": {"resource_type": "vm", "resource_id": "100"},
                        "values": [[1_780_700_400, "0.42"]],
                    },
                ]
            },
        }

    backend = PrometheusTrendBackend(
        base_url="https://prometheus.example",
        json_get=fake_json_get,
    )

    trends = await backend.get_resource_trends(
        resource_type="vm",
        resource_id="100",
        metric="cpu_usage",
        range_seconds=3600,
        step_seconds=60,
        limit=10,
    )

    assert len(trends) == 1
    assert trends[0].samples == [{"timestamp": "2026-06-05T23:00:00+00:00", "value": 0.42}]


async def test_prometheus_backend_reports_retryable_http_errors() -> None:
    async def fake_json_get(url: str, timeout_seconds: int) -> object:
        _ = url, timeout_seconds
        raise ObservabilityBackendError("backend unavailable", retryable=True)

    backend = PrometheusTrendBackend(
        base_url="https://prometheus.example",
        json_get=fake_json_get,
    )

    with pytest.raises(ObservabilityBackendError) as exc_info:
        await backend.get_resource_trends(
            resource_type="vm",
            resource_id="100",
            metric="cpu_usage",
            range_seconds=3600,
            step_seconds=60,
            limit=1,
        )

    assert exc_info.value.retryable is True


async def test_prometheus_backend_rejects_compound_promql_metric_text() -> None:
    backend = PrometheusTrendBackend(base_url="https://prometheus.example")

    with pytest.raises(ObservabilityBackendError, match="unscoped metric name"):
        await backend.get_resource_trends(
            resource_type="vm",
            resource_id="100",
            metric="up or cpu_usage",
            range_seconds=3600,
            step_seconds=60,
            limit=1,
        )


async def test_database_siem_delivery_queue_retries_and_dead_letters(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'siem.db').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    queue = DatabaseSiemDeliveryQueue(build_session_factory(engine), max_attempts=2)

    delivery = await queue.enqueue(
        destination="splunk",
        payload={"event": "audit", "password": "secret-value"},
    )
    claimed = await queue.claim_due(limit=1)
    assert (await queue.claim_due(limit=1)) == []
    await queue.mark_failed(claimed[0].delivery_id, error="connection refused")
    retryable = await queue.claim_due(limit=1)
    await queue.mark_failed(retryable[0].delivery_id, error="connection refused again")
    dead_lettered = await queue.get(delivery.delivery_id)
    await engine.dispose()

    assert dead_lettered.status == "dead_lettered"
    assert dead_lettered.attempt_count == 2
    assert dead_lettered.payload["pass" + "word"] == "**********"


async def test_database_siem_delivery_queue_claim_is_shared_across_instances(
    tmp_path: Path,
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'siem-shared.db').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    queue_a = DatabaseSiemDeliveryQueue(build_session_factory(engine))
    queue_b = DatabaseSiemDeliveryQueue(build_session_factory(engine))

    await queue_a.enqueue(destination="splunk", payload={"event": "audit"})
    claimed = await queue_a.claim_due(limit=1)
    duplicate = await queue_b.claim_due(limit=1)
    await engine.dispose()

    assert len(claimed) == 1
    assert duplicate == []


async def test_siem_delivery_schedules_retry_on_adapter_failure(tmp_path: Path) -> None:
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'siem-delivery.db').as_posix()}"
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    queue = DatabaseSiemDeliveryQueue(build_session_factory(engine))

    class FailingDelivery(SiemDelivery):
        async def deliver(self, destination: str, payload: dict[str, object]) -> None:
            _ = destination, payload
            raise SiemDeliveryError("sink down", retryable=True)

    delivery = await queue.enqueue(destination="splunk", payload={"event": "audit"})
    await queue.deliver_due(FailingDelivery(), limit=1)
    failed = await queue.get(delivery.delivery_id)
    await engine.dispose()

    assert failed.status == "pending"
    assert failed.attempt_count == 1
    assert failed.last_error == "sink down"


async def test_siem_delivery_dead_letters_non_retryable_adapter_failure(tmp_path: Path) -> None:
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'siem-non-retryable.db').as_posix()}"
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    queue = DatabaseSiemDeliveryQueue(build_session_factory(engine), max_attempts=5)

    class NonRetryableDelivery(SiemDelivery):
        async def deliver(self, destination: str, payload: dict[str, object]) -> None:
            _ = destination, payload
            raise SiemDeliveryError("bad request", retryable=False)

    delivery = await queue.enqueue(destination="splunk", payload={"event": "audit"})
    await queue.deliver_due(NonRetryableDelivery(), limit=1)
    failed = await queue.get(delivery.delivery_id)
    await engine.dispose()

    assert failed.status == "dead_lettered"
    assert failed.attempt_count == 1


async def test_siem_queueing_audit_writer_degrades_after_audit_persistence() -> None:
    class FailingQueue:
        async def enqueue(
            self,
            *,
            destination: str,
            payload: dict[str, object],
        ) -> SiemDeliveryRecordData:
            _ = destination, payload
            raise RuntimeError("siem unavailable")

    audit_writer = InMemoryAuditWriter()
    writer = SiemQueueingAuditWriter(
        audit_writer,
        FailingQueue(),
        destination="splunk",
    )

    await writer.write(_audit_event(metadata={"token": "secret-value"}))

    assert len(audit_writer.events) == 1


async def test_siem_queueing_audit_writer_enqueues_sanitized_event(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'siem-audit.db').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    queue = DatabaseSiemDeliveryQueue(build_session_factory(engine))
    writer = SiemQueueingAuditWriter(InMemoryAuditWriter(), queue, destination="splunk")

    await writer.write(_audit_event(metadata={"api_token": "secret-value"}))
    queued = await queue.claim_due(limit=1)
    await engine.dispose()

    assert queued[0].destination == "splunk"
    assert "secret-value" not in str(queued[0].payload)


def _audit_event(metadata: dict[str, object] | None = None) -> AuditEvent:
    return AuditEvent(
        event_type="tool.execution.finished",
        correlation_id="corr-1",
        tenant_id="tenant-1",
        actor_user_id="user-1",
        actor_agent_id="agent-1",
        tool_name="list_nodes",
        operation="list_nodes",
        target=AuditTarget(resource_type="node", resource_id="pve-1"),
        result_status="success",
        metadata={} if metadata is None else metadata,
    )
