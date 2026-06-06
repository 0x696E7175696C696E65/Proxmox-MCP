from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import uuid4

MetricStatus = Literal["success", "error", "denied"]
SiemFormat = Literal["splunk", "elk", "graylog", "wazuh", "loki"]


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
    payload = {"timestamp": timestamp, "event": event, **fields}
    if format_name == "splunk":
        return {"time": timestamp, "event": payload}
    if format_name == "elk":
        return {"@timestamp": timestamp, "event": {"action": event}, **fields}
    if format_name == "graylog":
        return {"version": "1.1", "short_message": event, "timestamp": timestamp, **fields}
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
