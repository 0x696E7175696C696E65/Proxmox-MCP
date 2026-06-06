from __future__ import annotations

import json

from proxmox_mcp.observability import (
    InMemoryMetricsRegistry,
    TraceSpan,
    format_siem_event,
    structured_log,
)


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
